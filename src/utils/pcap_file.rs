#![allow(dead_code)]
#![allow(non_camel_case_types)]
extern crate pcap;
use pcap::Packet;
use std::path::Path;
use std::ffi::CString;
use libc::{c_int, c_uint, c_char, c_uchar, timeval};


#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

pub enum pcap_t { }
pub enum pcap_dumper_t { }

extern "C" {
    pub fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
    pub fn pcap_open_dead(arg1: c_int, arg2: c_int) -> *mut pcap_t;
    pub fn pcap_dump(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) -> ();
    pub fn pcap_dump_close(arg1: *mut pcap_dumper_t) -> ();
    pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut c_char;
}

/// Abstraction for writing pcap savefiles, which can be read afterwards via `Capture::from_file()`.
pub struct Savefile {
    ptr_pcap_t: Unique<pcap_t>,
    ptr_pcap_dumper_t: Unique<pcap_dumper_t>,
}

impl Savefile {
    pub fn write(&mut self, packet: &Packet) {
        unsafe {
            pcap_dump(*self.ptr_pcap_dumper_t as _,
                        mem::transmute::<_, &pcap_pkthdr>(packet.header),
                        packet.data.as_ptr());
        }
    }

    pub fn new<P: AsRef<Path>>(path: P) -> Savefile {
        let name = CString::new(path.as_ref().to_str().unwrap()).unwrap();
        unsafe {
            let ptr_pcap_t = pcap_open_dead(1, 65535).as_mut().unwrap();
            let ptr_pcap_dumper_t = pcap_dump_open(ptr_pcap_t, name.as_ptr());
            Savefile { 
                ptr_pcap_t: Unique::new(ptr_pcap_t), 
                ptr_pcap_dumper_t: Unique::new( ptr_pcap_dumper_t ) 
            }
        }
    }

    pub fn null() -> Savefile {
        unsafe {
            Savefile {
                ptr_pcap_t: Unique::new(std::ptr::null_mut()),
                ptr_pcap_dumper_t: Unique::new(std::ptr::null_mut())
            }
        }
    }
}

impl Drop for Savefile {
    fn drop(&mut self) {
        unsafe { pcap_dump_close(*self.ptr_pcap_dumper_t) }
    }
}


// pcap/src/unique.rs
use std::fmt;
use std::mem;
use std::marker::PhantomData;
use std::ops::Deref;

pub struct Unique<T: ?Sized> {
    pointer: *const T,
    _marker: PhantomData<T>,
}

unsafe impl<T: Send + ?Sized> Send for Unique<T> {}
unsafe impl<T: Sync + ?Sized> Sync for Unique<T> {}

impl<T: ?Sized> Unique<T> {
    pub unsafe fn new(ptr: *mut T) -> Unique<T> {
        Unique {
            pointer: ptr,
            _marker: PhantomData,
        }
    }
    pub unsafe fn get(&self) -> &T {
        &*self.pointer
    }
    pub unsafe fn get_mut(&mut self) -> &mut T {
        &mut ***self
    }
}

impl<T: ?Sized> Deref for Unique<T> {
    type Target = *mut T;

    #[inline]
    fn deref(&self) -> &*mut T {
        unsafe { mem::transmute(&self.pointer) }
    }
}

impl<T> fmt::Pointer for Unique<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.pointer, f)
    }
}
