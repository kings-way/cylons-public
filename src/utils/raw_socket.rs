extern crate log;
extern crate libc;

use std::io;
use std::mem;
use std::net;
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

fn _main() {
    let interface_name = "lo";
    let socket_fd = match get_raw_socket(interface_name){
        Ok(fd) => fd,
        Err(err) => {
            error!("Error, {}", err);
            return;
        }
    };
    
    // 14 bytes at least
    let mut buffer: Vec<u8> =  "Hello, World!!".as_bytes().to_vec();
    match send_raw_data(socket_fd, &mut buffer){
        Ok(_) => (),
        Err(err) => {
            error!("Error, {}", err);
            return;
        }
    }
}


pub fn send_raw_data(socket_fd: i32, buf: &mut [u8]) -> Result<(), io::Error> {
    let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
    match unsafe {
        libc::send(socket_fd, buf_ptr, buf.len() as usize, 0)
        } {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(())
    }
}

pub fn get_raw_socket(iface: &str) -> Result<i32, io::Error> {
    let socket_fd;
    let mut iface = iface.to_owned();
    let ifname = iface.as_mut_ptr() as *mut libc::c_char;
    match unsafe {
        socket_fd = libc::socket(libc::PF_PACKET, libc::SOCK_RAW, 3);
        socket_fd
    } {
        -1 => return Err(io::Error::last_os_error()),
        _ => ()
    };

    match unsafe {
        let mut sa: libc::sockaddr_ll = mem::zeroed();
        sa.sll_family = libc::AF_PACKET as u16;
        sa.sll_protocol = libc::ETH_P_ALL as u16;
        sa.sll_ifindex = libc::if_nametoindex(ifname) as i32;

        let sa_ptr = mem::transmute::<*mut libc::sockaddr_ll, *mut libc::sockaddr>(&mut sa);
        libc::bind(socket_fd, sa_ptr, mem::size_of_val(&sa) as u32)
    } {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(socket_fd)
    }
}

pub fn get_original_dst(fd: i32) -> Result<(net::IpAddr, u16), io::Error> {
    let mut sa: libc::sockaddr_in;
    match unsafe {
        sa = mem::zeroed();
        let mut sa_len = mem::size_of_val(&sa) as u32;
        sa.sin_family = libc::AF_INET as u16;                   // only v4 for now

        let sa_ptr = mem::transmute::<*mut libc::sockaddr_in, *mut libc::c_void>(&mut sa);
        let sa_len_ptr = mem::transmute::<*mut libc::c_uint, *mut libc::socklen_t>(&mut sa_len);
        libc::getsockopt(fd, libc::SOL_IP, libc::SO_ORIGINAL_DST, sa_ptr, sa_len_ptr)
    } {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok((net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)).into(), u16::from_be(sa.sin_port)))
    }
}
