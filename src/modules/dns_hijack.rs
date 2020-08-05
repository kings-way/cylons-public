#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
extern crate log;
extern crate etherparse;
extern crate lazy_static;
use lazy_static::lazy_static;

use std::sync::{mpsc, Mutex};
use std::collections::HashMap;
use etherparse::PacketBuilder;
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

use crate::utils;

lazy_static! {
    static ref time_unix: u64           = utils::get_unix_time();
    static ref time_formatted: String   = utils::get_formatted_time();
    static ref module_type: u8          = utils::consts::MODULE_TYPE_ACTIVE;
    static ref module_name:&'static str = "DNS Hijack";
    static ref module_info:&'static str = "Hijack DNS Query on udp port 53";
    static ref risk_type: u8            = utils::consts::RISK_TYPE_NONE;
    static ref risk_level: u8           = utils::consts::RISK_LEVEL_LOG;
    static ref src: Mutex<String>       = Mutex::new(String::new());
}

pub fn get_packet(pkt: &[u8], HIJACK_RECORD_MAP: &HashMap<String, String>, db_tx: mpsc::Sender<String>) -> Option<Vec<u8>> {
    let pkt = etherparse::PacketHeaders::from_ethernet_slice(pkt).unwrap();
    *src.lock().unwrap() = utils::src_dst_proto_from_IpHeader(&pkt.ip).0;

    let (index, _query_type, query_name) = Parse_Query(pkt.payload);
    let (query_name, record) = 
                if let Some(record) = HIJACK_RECORD_MAP.get(query_name.as_str()) {
                    (query_name.as_str(), record)
                }
                else if let Some(record) = HIJACK_RECORD_MAP.get("*") { 
                    ("*", record)
                }
                else { 
                    return None;
                };
    debug!("DNS HIJACK: {} IN A {}", query_name, record);
    db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, 'DNS Hijack: {} IN A {}', 0 )", 
                        *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                        *module_info, *risk_type, *risk_level, query_name, record )).unwrap();

    let dst_mac = pkt.link.as_ref().unwrap().source;
    let src_mac = pkt.link.as_ref().unwrap().destination;
    let builder = PacketBuilder:: ethernet2(src_mac, dst_mac);
    let builder = match pkt.ip.as_ref().unwrap() {
        etherparse::IpHeader::Version4(header) => {
            let dst_addr = header.source;
            let src_addr = header.destination;
            builder.ipv4(src_addr, dst_addr, 64)
        }, 
        etherparse::IpHeader::Version6(header) =>{
            let dst_addr = header.source;
            let src_addr = header.destination;
            builder.ipv6(src_addr, dst_addr, 64)
        }
    };

    let transport = pkt.transport.unwrap().udp().unwrap();
    let dst_port = transport.source_port;
    let src_port = transport.destination_port;
    let builder = builder.udp(src_port, dst_port);
 
    let mut payload = vec![                                 // build up response header
        pkt.payload[0], pkt.payload[1], // transaction id
        0x81, 0x80,                     // flags
        0x00, 0x01,                     // questions
        0x00, 0x01,                     // answer prs
        0x00, 0x00,                     // authority prs
        0x00, 0x00,                     // additional prs
    ];
    payload.extend(pkt.payload[12..index].to_owned());      // copy one query section
    payload.extend(&[                                       // build up answer section
                    0xc0, 0x0c,             // 
                    0x00, 0x01,             // type: A      // only support A record for now.
                    0x00, 0x01,             // class: IN
                    0x00, 0x00, 0x00, 0xff, // ttl
                    0x00, 0x04,             // data length
                    ]);
    payload.extend(&ipv4_to_bytes(record));

    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(
                        builder.size(payload.len()));
    //serialize
    builder.write(&mut result, &payload).unwrap();
    Some(result)
}

pub fn ipv4_to_bytes(ip: &str) -> [u8; 4] {
    let mut result:[u8; 4] = [0; 4];
    let mut index = 0;

    for num in ip.trim().split('.') {
        result[index] = num.to_string().parse::<u8>().unwrap();
        index += 1;
    }
    result
}

pub fn Parse_Query(packet: &[u8]) -> (usize, String, String) {
    // we only parse the first query, and only A record
    let mut index = 12;
    let mut query_type = String::new();
    let mut query_name = String::new();
    
    loop{
        let mut count = packet[index] as u8;
        if count == 0 {
            break;
        }
        while count > 0 {
            index += 1;
            count -= 1;
            query_name.push(packet[index] as char);
        }
        query_name.push('.');
        index += 1;
    }

    index += 1;
    if packet[index] as u8 == 0x00 && packet[index+1] as u8 == 0x01{
        query_type.push_str("A");
    }
    else if packet[index] as u8 == 0x00 && packet[index+1] as u8 == 0x1C {
        query_type.push_str("AAAA");
    }
    else{
        query_type.push_str("unknown");
    }

    index += 4;
    let query_name = query_name.trim_end_matches('.').to_string();

    (index, query_type, query_name)
}
