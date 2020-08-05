#![allow(non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;
extern crate log;
extern crate nom;
extern crate pcap;
extern crate ctrlc;
extern crate regex;
extern crate num_cpus;
extern crate tls_parser;
extern crate etherparse;
extern crate threadpool;

use std::str;
use std::process;
use regex::Regex;
use threadpool::ThreadPool;
use etherparse::SlicedPacket;
use std::collections::HashMap;
use std::sync::{mpsc, Arc};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

mod utils;
mod config;
mod modules;
mod database;

use database::DB;
use config::tcp_rule::TcpRule;
use utils::{raw_socket, consts};

fn main() {
    utils::my_log::init_with_level(Level::Debug).unwrap();

    let (RuleDNS, RuleTCP, TOML_CONFIG) = config::parse_config();
    let CONF_IFACE      = TOML_CONFIG["interface"].as_str().unwrap().to_owned();
    let CONF_FILTER     = TOML_CONFIG["filter"].as_str().unwrap().to_owned();
    let CONF_DB_PATH    = TOML_CONFIG["db_path"].as_str().unwrap().to_owned();
    let CONF_TLS_MITM   = TOML_CONFIG["tls_mitm"]["enabled"].as_bool().unwrap();
    let CONF_TLS_CHECK  = TOML_CONFIG["tls_check"]["enabled"].as_bool().unwrap();
    let CONF_PCAP_DUMP  = TOML_CONFIG["pcap_dump"]["enabled"].as_bool().unwrap();
    let CONF_API_ENABLE = TOML_CONFIG["api"]["enabled"].as_bool().unwrap();
    let CONF_API_LISTEN = TOML_CONFIG["api"]["listen_addr"].as_str().unwrap().to_owned();
    let CONF_PCAP_FILE_DIR  = TOML_CONFIG["pcap_dump"]["file_dir"].as_str().unwrap();
    let CONF_SSLLAB_ENABLE  = TOML_CONFIG["tls_check"]["ssllab_scan_enabled"].as_bool().unwrap();
    let CONF_TLS_MITM_DOMAIN= TOML_CONFIG["tls_mitm"]["mitm_domain"].as_array().unwrap().to_owned();
    let CONF_TLS_MITM_LISTEN= TOML_CONFIG["tls_mitm"]["mitm_listen"].as_str().unwrap().to_owned();
    let SENSITIVE_RE        = Regex::new(TOML_CONFIG["sensitive_info"]["match_pattern"].as_str().unwrap()).unwrap();
    
//    debug!("RuleDNS: {:?}", RuleDNS);
//    debug!("RuleTCP: {:?}", RuleTCP);
    // initialize the dict
    debug!("Length of ENGLISH_DICT: {}",utils::consts::ENGLISH_DICT.len());

    *consts::DB_PATH.lock().unwrap() = CONF_DB_PATH;
    let (raw_tx, raw_rx) = mpsc::channel();
    let (packet_tx, packet_rx) = mpsc::channel();
    let (parsed_packet_tx, parsed_packet_rx) = mpsc::channel();
    let (db_writer_tx, db_writer_rx) = mpsc::channel();
    let db_rw = DB::new(consts::DB_READ_WRITE).expect("Failed connecting to sqlite");       // make sure only one read&write connection
//  let db_rd = DB::new(consts::DB_READ_ONLY).expect("Failed connecting to sqlite");        // other threads are ok to get read only connection

    let sock_fd = raw_socket::get_raw_socket(&CONF_IFACE).unwrap_or_else(|err|{
        error!("Failed to open raw socket, {}", err);
        process::exit(-1);
    });

    let RuleDNS = Arc::new(RuleDNS);
    let RuleTCP = Arc::new(RuleTCP);
    let SENSITIVE_RE = Arc::new(SENSITIVE_RE);

    // TODO need some error handling
    let (pcap_filename, mut pcap_file_writer) = match CONF_PCAP_DUMP {
        true => {
            let pcap_filename = utils::get_pcap_filename(CONF_PCAP_FILE_DIR);
            let pcap_file_writer = utils::pcap_file::Savefile::new(&pcap_filename);
            (pcap_filename, pcap_file_writer)
        },
        false => ("None".to_owned(), utils::pcap_file::Savefile::null())
    };

    let pool = ThreadPool::new(num_cpus::get() + 6 + 1);    // 6 + n + 1 threads: main_thread, task_capture, packet_logger, db_writer, api, mitm/sni_proxy
    let _db_tx = db_writer_tx.clone();
    reg_signal(raw_tx.clone());

    if CONF_TLS_MITM {
        let _db_tx = db_writer_tx.clone();
        pool.execute(move || modules::tls_mitm::run(&CONF_TLS_MITM_DOMAIN, &CONF_TLS_MITM_LISTEN, _db_tx));
    }
    if CONF_API_ENABLE {
        pool.execute(move || modules::api::run(&CONF_API_LISTEN, parsed_packet_rx));
    }
    pool.execute(move || task_capture(&CONF_IFACE, &CONF_FILTER, raw_tx));
    pool.execute(move || database::db_writer(db_rw, db_writer_rx));
    pool.execute(move || modules::packet_logger::run(packet_rx, _db_tx, parsed_packet_tx));

    info!("main thread started!  ({} {}), interface: [{}], filter: [{}], pcap file: [{}], API: [http://{}]",
            env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"), 
            TOML_CONFIG["interface"].as_str().unwrap(),
            TOML_CONFIG["filter"].as_str().unwrap(),
            &pcap_filename,
            &TOML_CONFIG["api"]["listen_addr"].as_str().unwrap());

    for cap in &raw_rx {
        let (header, data) = match cap {
            Some((v1, v2)) => (v1, v2),
            None => {
                error!("main thread: exiting now");
                break;
            }
        };

        // write to pcap file
        if CONF_PCAP_DUMP {
            pcap_file_writer.write(&pcap::Packet {
                header: &header,
                data: &data
            });
        }

        // start parse
        let t_sec = header.ts.tv_sec;
        let t_usec = header.ts.tv_usec;
        let data = Arc::new(data);
        let _data = data.clone();
        let _db_tx = db_writer_tx.clone();
        // using SlicedPacket instead of PacketHeaders, no need to parsing all headers now
        let sliced_packet = match SlicedPacket::from_ethernet(&data) {
            Ok(value) => value,
            Err(err) => {
                error!("main thread: packet parsing error: {}", err);
                continue;
            }
        };

        // UDP
        if let Some(etherparse::TransportSlice::Udp(header)) = &sliced_packet.transport {
            if header.destination_port() == 53 {
                let _RuleDNS = Arc::clone(&RuleDNS);
                pool.execute(move||task_dns_hijack(_data, _RuleDNS, sock_fd, _db_tx));
            }
            else if header.source_port() == 443 || header.destination_port() == 443 {
                // #TODO DTLS
                // todo!("DTLS Check");
            }
            else {
                let _SENSITIVE_RE = Arc::clone(&SENSITIVE_RE);
                pool.execute(move||task_plaintext_scan(_data, _SENSITIVE_RE, _db_tx));
            }
         }
        // TCP
        else if let Some(etherparse::TransportSlice::Tcp(header)) = &sliced_packet.transport{
            let _RuleTCP = Arc::clone(&RuleTCP);
            let length = sliced_packet.payload.len() as u16;

            if header.syn() || header.ack() || header.psh() {
                let _db_tx2 = _db_tx.clone();
                pool.execute(move||task_tcp_hijack(_data, _RuleTCP, sock_fd, _db_tx2));

                let _data = data.clone();
                if (header.source_port() == 443 || header.destination_port() == 443) && length > 5 && CONF_TLS_CHECK {
                    match (sliced_packet.payload[0], sliced_packet.payload[5]) {
                        (0x16, 0x1) => pool.execute(move||task_tls_check(_data, CONF_SSLLAB_ENABLE, _db_tx)),    // handshake: ClientHello
                        (0x16, 0x2) => pool.execute(move||task_tls_check(_data, CONF_SSLLAB_ENABLE, _db_tx)),    // handshake: ServerHello
                        _ => (),
                    }
                }
                else if length > 0 {          // sensitive string scan
                    let SENSITIVE_RE = Arc::clone(&SENSITIVE_RE);
                    pool.execute(move||task_plaintext_scan(_data, SENSITIVE_RE, _db_tx));
                }
            }
        }
        packet_tx.send((t_sec, t_usec, data)).unwrap();
    }

    drop(raw_rx);
    drop(packet_tx);
//    pool.join();
}

fn task_tls_check(data: Arc<Vec<u8>>, CONF_SSLLAB_ENABLE: bool, db_tx: mpsc::Sender<String>) {
    modules::tls_check::check(&data, CONF_SSLLAB_ENABLE, db_tx);
}

fn task_dns_hijack(data: Arc<Vec<u8>>, RuleDNS: Arc<HashMap<String, String>>, sock_fd: i32, db_tx: mpsc::Sender<String>) {
    if let Some(mut packet) = modules::dns_hijack::get_packet(&data, &RuleDNS, db_tx){
        match raw_socket::send_raw_data(sock_fd, &mut packet){
            Ok(_) => (),
            Err(err) => error!("tast_dns_hijack: {}", err),
        }
    }
}

fn task_tcp_hijack(data: Arc<Vec<u8>>, RuleTCP: Arc<TcpRule>, sock_fd: i32, db_tx: mpsc::Sender<String>) {
    if let Some(mut packet) = modules::tcp_hijack::get_packet(&data, &RuleTCP, db_tx){
        match raw_socket::send_raw_data(sock_fd, &mut packet){
            Ok(_) => (),
            Err(err) => error!("task_tcp_reset: {}", err),
        }

    }
}

// check for plain text data and sensitive data
fn task_plaintext_scan(data: Arc<Vec<u8>>, SENSITIVE_RE: Arc<Regex>, db_tx: mpsc::Sender<String>){
    modules::plaintext::check(&data, SENSITIVE_RE, db_tx);
}

fn reg_signal(tx: mpsc::Sender<Option<(pcap::PacketHeader, Vec<u8>)>>) {
    ctrlc::set_handler(move || {
        error!("Got SIGINT or SIGTERM");
        // clear iptables rules
        #[allow(unused_must_use)]
        {
            process::Command::new("sh").arg("-c")
                    .arg("iptables -t nat -D PREROUTING -p tcp -m multiport --dports 443,8443 -j CYLONS_TLS_MITM 2>/dev/null;\
                          iptables -t nat -F CYLONS_TLS_MITM 2>/dev/null;\
                          iptables -t nat -X CYLONS_TLS_MITM 2>/dev/null;").output();
        }
        // notify the main thread to stop
        tx.send(None).unwrap();
    }).unwrap();
}

//fn task_capture(CONF_IFACE:&str, CONF_FILTER:&str, tx: mpsc::Sender<Option<(i64, i64, Vec<u8>)>>, fd: RawFd) {
fn task_capture(CONF_IFACE:&str, CONF_FILTER:&str, tx: mpsc::Sender<Option<(pcap::PacketHeader, Vec<u8>)>>) {
    let mut iface_cap = pcap::Capture::from_device(CONF_IFACE)
                        .unwrap_or_else(|err|{
                            error!("Failed to open device:{}, {}", CONF_IFACE, err);
                            process::exit(-1);
                        })
                        .immediate_mode(true)
                        .promisc(true)
                        .open()
                        .unwrap_or_else(|err|{
                            error!("Failed to open device: {}, {}", CONF_IFACE, err);
                            process::exit(-1);
                        });
    iface_cap.filter(CONF_FILTER).unwrap_or_else(|err|{
        error!("Failed to set filter: {}", err);
        process::exit(-1);
    });

    while let Ok(packet) = iface_cap.next() {
//        let t_sec = packet.header.ts.tv_sec;
//        let t_usec = packet.header.ts.tv_usec;

        // not possible to send T 'packet', or &packet
        match tx.send(Some((*packet.header, Vec::from(packet.data)))) {
//        match tx.send(Some((t_sec, t_usec, Vec::from(packet.data)))) {
            Ok(_) => (),
            Err(err) => {
                error!("tast_capture: tx send error: {}\n Quitting...", err);
                break;
            }
        };
    }
}
