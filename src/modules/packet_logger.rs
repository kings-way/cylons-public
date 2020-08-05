extern crate log;
extern crate etherparse;

use std::sync::{mpsc, Arc};
use std::net::{Ipv4Addr, Ipv6Addr};
use etherparse::SlicedPacket;

#[allow(unused_imports)]
use std::io::{self, Write};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

use crate::utils;

pub fn run(packet_rx: mpsc::Receiver<(i64, i64, Arc<Vec<u8>>)>, db_tx: mpsc::Sender<String>,
            parsed_packet_tx: mpsc::Sender<(String, String, u16, String, u16, String, u16, String)>) {
    let mut sport: u16;
    let mut dport: u16;
    let mut length: u16;
    let mut parsed_info: String;
    let mut parsed_protocol: &str;

    let mut time_unix: String;
    let mut time_formatted: String;

    for (t_sec, t_usec, data) in packet_rx {
//        info!(".");
//        io::stdout().flush().unwrap();

        parsed_info = "".to_owned();
        time_unix = format!("{}.{:06}", t_sec, t_usec); // sqlite real/double not ok for 6 digits after '.'
//        time_formatted = time::at(time::Timespec::new(t_sec, t_usec as i32 * 1000)).strftime("%Y%m%d %T").unwrap().to_string();
        time_formatted = utils::local_time("%Y%m%d %T", Some(t_sec)).unwrap();
        time_formatted.push_str(&format!(".{:03}", t_usec / 1000));

        // using SlicedPacket instead of PacketHeaders, no need to parsing all headers now
        let sliced_packet = SlicedPacket::from_ethernet(&data).unwrap();
        let (mut src, mut dst, protocol) = utils::src_dst_proto_from_IpSlice(&sliced_packet.ip);

        // UDP
        if let Some(etherparse::TransportSlice::Udp(header)) = &sliced_packet.transport {
            parsed_protocol = "UDP";
            sport = header.source_port();
            dport = header.destination_port();
            length = header.length() - 8;

            if sport == 53 || dport == 53 || sport == 5353 || dport == 5353 {
                parsed_protocol = if sport == 53 || dport == 53 {"DNS"} else {"MDNS"};
                parsed_info = parse_dns(sliced_packet.payload).iter().map(|i|{format!("{:?}\n", i)}).collect::<String>();
                parsed_info = parsed_info.trim().to_owned();
            }
            else if sport == 443 || dport == 443 {
                parsed_protocol = "DTLS";
                if length > 13 {
                    parsed_info = match (sliced_packet.payload[0], sliced_packet.payload[13]) {
                            (0x16, 0x1) => "Client Hello".to_owned(),
                            (0x16, 0x2) => "Server Hello".to_owned(),
                            (0x14, _) => "Change Cipher Spec".to_owned(),
                            (0x17, _) => "Application Data".to_owned(),
                            (0x15, level)=> format!("Alert: (Level: {}, Desc: {})",
                                                utils::consts::TLS_ALERT_LEVEL.get(&level).unwrap_or_else(||&"Unknown Level"),
                                                utils::consts::TLS_ALERT_DESC.get(&sliced_packet.payload[14]).unwrap_or_else(||&"Unknown Desc")
                                            ),
                            _ => "Application Data (or Handshake or Unknown)".to_owned(),
                    };
                }
            }
            else if sport == 123 || dport == 123 {
                parsed_protocol = "NTP"
            }
            else if sport == 1900 || dport == 1900 {
                parsed_protocol = "SSDP"
            }
        }
        // TCP
        else if let Some(etherparse::TransportSlice::Tcp(header)) = &sliced_packet.transport{
            parsed_protocol = "TCP";
            sport = header.source_port();   
            dport = header.destination_port();
            length = sliced_packet.payload.len() as u16;

            if sport == 443 || dport == 443 {
                parsed_protocol = "TLS";
                if length > 5 {
                    parsed_info = match (sliced_packet.payload[0], sliced_packet.payload[5]) {
                            (0x16, 0x1) => "Client Hello".to_owned(),
                            (0x16, 0x2) => "Server Hello".to_owned(),
                            (0x14, _) => "Change Cipher Spec".to_owned(),
                            (0x17, _) => "Application Data".to_owned(),
                            (0x15, level)=> format!("Alert: (Level: {}, Desc: {})",
                                                utils::consts::TLS_ALERT_LEVEL.get(&level).unwrap_or_else(||&"Unknown Level"),
                                                utils::consts::TLS_ALERT_DESC.get(&sliced_packet.payload[6]).unwrap_or_else(||&"Unknown Desc")
                                            ),
                            _ => "Application Data (or Handshake or Unknown)".to_owned(),
                    };
                }
            }
            else if sport == 53 || dport == 53 || sport == 5353 || dport == 5353 {
                parsed_protocol = if sport == 53 || dport == 53 {"DNS(TCP)"} else {"MDNS(TCP)"};
                if length > 0 {
                    parsed_info = parse_dns(&sliced_packet.payload[2..]).iter().map(|i|{format!("{:?}\n", i)}).collect::<String>();
                    parsed_info = parsed_info.trim().to_owned();
                }
            }

            let mut flags: Vec<&str> = vec![];
            let (seq, ack) = parse_tcp_header(header, &mut flags);
            parsed_info = format!("{} seq:{},ack:{},{:?})", parsed_info, seq, ack, flags);
        }
        
        // ICMP
        else if protocol == 0x01 {
            sport = 0;  dport = 0;
            length = sliced_packet.payload.len() as u16;
            parsed_protocol = "ICMP";
            parsed_info = parse_icmp(sliced_packet.payload);
        }
        // ICMPv6
        else if protocol == 0x3A {
            sport = 0;  dport = 0;
            length = sliced_packet.payload.len() as u16;
            parsed_protocol = "ICMPv6";
            parsed_info = parse_icmpv6(sliced_packet.payload);
        }

        // this is for Non-IP Protocol, check the EtherType
        else if protocol == 0xFF {
            sport = 0;  dport = 0;
            length = sliced_packet.payload.len() as u16;
            let (_src, _dst, ethertype) = utils::src_dst_proto_from_LinkSlice(&sliced_packet.link);
            src = _src;
            dst = _dst;
            parsed_protocol = utils::get_eth_protocol_name(ethertype);
        }

        // Other IP Protocol
        else {
            trace!("{} => {}", src, dst);
            trace!("{:?}", sliced_packet);
            sport = 0;
            dport = 0;
            length = sliced_packet.payload.len() as u16;
            parsed_protocol = utils::get_ip_protocol_name(protocol);
        }

        // for Non-IP Protocol and ICMP
        if protocol == 0xFF || protocol == 0x01 || protocol == 0x3A {
            info!("{} => {}, {}, {}, {}", src, dst, parsed_protocol, length, parsed_info);
        }
        else{
            info!("{}:{} => {}:{}, {}, {}, {}", src, sport, dst, dport, parsed_protocol, length, parsed_info);
        }
        parsed_packet_tx.send((time_formatted.clone(), src.clone(), sport, dst.clone(), dport,
                                parsed_protocol.to_owned(), length, parsed_info.trim().replace("'", "''"))).unwrap();
        db_tx.send(format!("insert into t_traffic values (null, '{}', '{}', '{}', '{}', {}, {}, '{}', {}, '{}')",
                   time_unix, time_formatted, src, dst, sport, dport, parsed_protocol, length, parsed_info.trim().replace("'", "''"))).unwrap();
                    // SQL: use '' to escape '
    }
}

pub fn parse_icmp(packet: &[u8]) -> String {
    // https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    // only parse the "type" here, leave detailed "code" to the future
    match packet[0] {
        0x08 => "Echo Request",
        0x00 => "Echo Reply",
        0x03 => "Destination Unreachable",
        0x09 => "Router Advertisement",
        0x0A => "Router Solicitation",
        0x0B => "Time exceeded",
        _ => "unknow ICMP type"
    }.to_string()
}


pub fn parse_icmpv6(packet :&[u8]) -> String {
    match packet[0] {
        0x01 => "Destination Unreachable",
        0x02 => "Packet too big",
        0x03 => "Time exceeded",
        0x04 => "Parameter problem",
        0x80 => "Echo Request",
        0x81 => "Echo Reply",
        0x85 => "Router Solicitation (NDP)",
        0x86 => "Router Advertisement (NDP)",
        0x87 => "Neighbor Solicitation (NDP)",
        0x88 => "Neighbor Advertisement (NDP)",
        0x89 => "Redirect Message (NDP)",
        0x8A => "Router Renumbering ",
        _ => "unknown ICMPv6 type"
    }.to_owned()
}

pub fn parse_tcp_header(header: &etherparse::TcpHeaderSlice, flags: &mut Vec<&str>) -> (u32, u32) {
    // TODO need a smarter way to parse flags
    if header.syn() {
        flags.push("SYN");
    }
    if header.ack() {
        flags.push("ACK");
    }
    if header.psh() {
        flags.push("PSH");
    }
    if header.rst() {
        flags.push("RST");
    }
    if header.fin() {
        flags.push("FIN");
    }
    if header.urg() {
        flags.push("URG");
    }
    (header.sequence_number(), header.acknowledgment_number())
}


//[("domain name", "AAAA", "IN", "?")]
pub fn parse_dns(packet: &[u8]) -> Vec<(String, String, String, String)> {
    let is_query = match packet[2] & 0x80 {
        0x00 => true,
        0x80 => false,
        _ => false,
    };

    let questions = read_u16(&packet[4..]);
    let answers = read_u16(&packet[6..]);
    let mut count = 0;
    let mut index = 12;
    let mut result = Vec::new();

    
    while count < questions {
        let (name_size, domain_name) = read_domain_name(&packet, index, 0);
        index += name_size;
        let record_type = match read_u16(&packet[index..]) {
            0x0001 => "A",
            0x0002 => "NS",
            0x0006 => "SOA",
            0x000C => "PTR",
            0x000D => "HINFO",
            0x0010 => "TXT",
            0x001C => "AAAA",
            0x0005 => "CNAME",
            0x000F => "MX",
            0x0021 => "SRV",
            0x00FF => "ANY",
            _ => "unknown type",
        } ;

        index += 2;
        let record_class = match read_u16(&packet[index..]) {
            0x0001 => "IN",
            0x8001 => "IN (mdns QU)",           // MDNS query use this means it accepts unicast as well
            _ => "unknown class",
        };
        index += 2;
        
        // we presume there is only one query record
        if is_query {
             result.push((domain_name, record_class.to_owned(), record_type.to_owned(), "?".to_owned()));
        }
        else if !is_query && answers == 0 {     // dns response: no record
            result.push((domain_name, record_class.to_owned(), record_type.to_owned(), "[not found]".to_owned()));
        }
        count += 1;
    }
    if result.len() > 0 && answers == 0 {
        return result;
    }


    // Parse Ansers
    count = 0;
    result.clear();
    while count < answers {
        let (readsize, _domain_name) =  read_domain_name(&packet, index, 0);
        index += readsize;              // for DNS response, the readsize is always 2 (0xCX XX), for mDNS response, the readsize varies
        let _record_type = match read_u16(&packet[index..]) {
            0x0001 => "A",
            0x0002 => "NS",
            0x0006 => "SOA",
            0x000C => "PTR",
            0x000D => "HINFO",
            0x0010 => "TXT",
            0x001C => "AAAA",
            0x0005 => "CNAME",
            0x000F => "MX",
            0x0021 => "SRV",
            0x00FF => "ANY",
            _ => "unknown type",
        };
        let _record_class = match read_u16(&packet[index+2..]) {
            0x0001 => "IN",
            0x8001 => "IN (mdns cache flush)",  // mdns response use this to indicate cache flush
            _ => "unknown class",
        };

        index += 8;
        let data_len = read_u16(&packet[index..]);
        index += 2;
        let data = if _record_type == "A" { // && data_len == 4 {
            format!("{}", Ipv4Addr::new(packet[index], packet[index+1], packet[index+2], packet[index+3]))
        }
        else if _record_type == "AAAA"{ // && data_len == 16{
            let mut _data = [0u8; 16]; 
            _data.copy_from_slice(&packet[index..index+16]);
            format!("{}", Ipv6Addr::from(_data))
        }
        else if _record_type == "unknown type" {
            "unknown data".to_owned()
        }
        else if _record_type == "SRV" {
            parse_dns_SRV(&packet, index)
        }
        else {  // for CNAME, NS, MX, PTR, TXT, SOA and more
            let _index = if _record_type == "MX" {index + 2} else {index};  // skip MX preference
            let _data_len = if _record_type == "TXT" {data_len} else {0};
            read_domain_name(&packet, _index, _data_len).1       // for TXT, we have to specify the max len read
        };

        index += data_len as usize;
        result.push((_domain_name, _record_class.to_owned(), _record_type.to_owned(), data));
        count += 1;
    }

    return result;
}

pub fn parse_dns_SRV(packet :&[u8], index: usize) -> String{
    let mut _index = index;
    let priority = read_u16(&packet[_index..]);
    _index += 2;
    let weight = read_u16(&packet[_index..]);
    _index += 2;
    let port = read_u16(&packet[_index..]);
    _index += 2;
    let target = read_domain_name(packet, _index, 0).1;
    format!("priority:{}, weight:{}, port:{}, target:{}",priority, weight, port, target)
}

pub fn read_u16(packet :&[u8]) -> u16{
    ((packet[0] as u16) << 8) + packet[1] as u16
}

pub fn read_domain_name(packet: &[u8], index: usize, data_len: u16) -> (usize, String) {
    let mut _index = index;
    let mut index_before_first_seek = 0;
    let mut data_len = if data_len == 0 { 0xffff } else { data_len };
    let mut data: Vec<u8> = Vec::new();
    while data_len > 0{
        data_len -= 1;
        let mut count = packet[_index];
        match count {
            0x00 => break,
            _ if count >> 4 == 0xc => {                 // DNS Name Compression or  Compacted-DNS
                if index_before_first_seek == 0 {       // only assign to it at first jump
                    index_before_first_seek = _index + 2;
                }
                _index = ((count as usize & 0x0f) << 8) + packet[_index+1] as usize;
                //_index = packet[_index+1] as usize;
                continue;
            },
            _ => ()
        }
        while count > 0 && data_len > 0{
            _index += 1;
            count -= 1;
            data_len -= 1;
            data.push(packet[_index]);
        }
        data.push('.' as u8);
        _index += 1;
    }

    _index += 1;
    let readsize = match _index > index {
        true => _index - index,
        _ => index_before_first_seek - index,         //  Compacted-DNS, we have jumped to different locations inside the packet based on offset.
    };
    let data_utf8 = String::from_utf8_lossy(&data);
//    debug!("---- call read_domain_name, index: {}, data_len: {}, readsize: {}, name: {}", index, data_len, readsize, data);
    (readsize, data_utf8.trim_end_matches('.').to_string())
}
