extern crate etherparse;

pub mod my_log;
pub mod consts;
pub mod pcap_file;
pub mod raw_socket;
#[cfg(target_pointer_width = "32")]
use std::convert::TryFrom;


use std::net::{Ipv4Addr, Ipv6Addr};


pub fn ipv4_str_to_int(ip_or_port: &str) -> u32 {
    if ip_or_port == "*" {
        return 0;
    }

    else if !ip_or_port.contains('.') {
        ip_or_port.to_string().parse::<u32>().expect("Error parsing port number to int")
    }
    else {
        let mut index = 0;
        let mut result:[u8; 4] = [0; 4];
        for num in ip_or_port.trim().split('.'){
            result[index] = num.to_string().parse::<u8>().unwrap();
            index += 1;
        }
        u32::from_be_bytes(result)
    }
}

pub fn eth_addr_to_string(addr: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        addr[4],
        addr[5]
        )
}

// get UNIX TimeStamp with std::time
pub fn get_unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

// get formatted time string with crate time
pub fn get_formatted_time() -> String {
//    time::now().strftime("%Y%m%d %T").unwrap().to_string()
    local_time("%Y%m%d %T", None).unwrap()
}

pub fn get_pcap_filename(dir: &str) -> String {
    format!("{}/{}",
        dir.trim_end_matches("/"),
//        time::now().strftime("Cylons_%Y-%m-%d_%H-%M-%S.pcap").unwrap().to_string()
        local_time("Cylons_%Y-%m-%d_%H-%M-%S.pcap", None).unwrap()
    )
}

pub fn get_ip_protocol_name(id: u8) -> &'static str {
    let id = id as usize;
    if id <= consts::IP_PROTOCOL.len() {
        return consts::IP_PROTOCOL[id]
    }
    else {
        return "unknown"
    }
}

pub fn get_eth_protocol_name(id: u16) -> &'static str {
    consts::ETH_PROTOCOL.get(&id).unwrap_or_else(||&"Unknown EtherType")
}


pub fn src_dst_proto_from_IpHeader(ip: &Option<etherparse::IpHeader>) -> (String, String, String) {
    match ip {
        Some(etherparse::IpHeader::Version4(h)) => (format!("{}", Ipv4Addr::from(h.source)), format!("{}", Ipv4Addr::from(h.destination)), get_ip_protocol_name(h.protocol).to_owned()),
        Some(etherparse::IpHeader::Version6(h)) => (format!("{}", Ipv6Addr::from(h.source)), format!("{}", Ipv6Addr::from(h.destination)), get_ip_protocol_name(h.next_header).to_owned()),
        _ => ("Unknown src".to_owned(), "Unknown dst".to_owned(), "Unknown protocol".to_owned()),
    }
}

pub fn src_dst_proto_from_LinkSlice(link: &Option<etherparse::LinkSlice>) -> (String, String, u16) {
    match link {
        Some(etherparse::LinkSlice::Ethernet2(eth)) =>
                (eth_addr_to_string(eth.source()), eth_addr_to_string(eth.destination()), eth.ether_type()),
        _ => ("Unknown Ether src".to_owned(), "Unknown Ether dst".to_owned(), 0xFFFF),

    }
}
pub fn src_dst_proto_from_IpSlice(ip: &Option<etherparse::InternetSlice>) -> (String, String, u8) {
    match ip {
        Some(etherparse::InternetSlice::Ipv4(h)) => (format!("{}", h.source_addr()), format!("{}", h.destination_addr()), h.protocol()),
        Some(etherparse::InternetSlice::Ipv6(h, _ext)) => (format!("{}", h.source_addr()), format!("{}", h.destination_addr()), h.next_header()),
        _ => ("Unknown src".to_owned(), "Unknown dst".to_owned(), 0xFF),
    }
}

extern "C" {
    fn strftime(
        s: *mut libc::c_char,
        max: libc::size_t,
        format: *const libc::c_char,
        tm: *const libc::tm,
    ) -> usize;
}

pub fn local_time(fmt: &str, time_now: Option<i64>) -> Option<String> {
    let time_now = match time_now {
        Some(t) => unsafe {
            #[cfg(target_pointer_width = "32")]
            let t: i32 = i32::try_from(t).unwrap();
            libc::localtime(&t)
        },
        None => unsafe {
            let t = libc::time(0 as *mut _);
            libc::localtime(&t)
        }
    };

    const BUF_SIZE: usize = 4096;
    let mut buf = [0u8; BUF_SIZE];
    let fmt = std::ffi::CString::new(fmt).unwrap();
    let size = unsafe { strftime(buf.as_mut_ptr() as _, BUF_SIZE, fmt.as_ptr() as *const _, time_now as *const _) };

    match size > 0 {
        true => Some(String::from_utf8_lossy(&buf[..size]).to_string()),
        false => None
    }
}
