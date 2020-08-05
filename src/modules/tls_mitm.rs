#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_must_use)]
#![allow(non_upper_case_globals)]
extern crate log;
extern crate nom;
extern crate rustls;
extern crate openssl;
extern crate tls_parser;
extern crate lazy_static;

use std::io;
use std::net;
use std::time;
use std::thread;
use std::sync::mpsc;
use std::error::Error;
use std::io::prelude::*;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::os::unix::io::AsRawFd;
use std::collections::{HashSet, HashMap};

use openssl::ssl;
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509Name};

use nom::Err;
use rustls::Session;
use rustls::ServerConfig;
use rustls::ServerSession;
use rustls::internal::pemfile;
use lazy_static::lazy_static;
use log::{trace, debug, info, warn, error};
use tls_parser::{TlsMessage, TlsMessageHandshake, tls_extensions};

use crate::utils;
use crate::config;

lazy_static! {
    static ref module_type: u8          = utils::consts::MODULE_TYPE_ACTIVE;
    static ref module_name:&'static str = "TLS MITM Check";
    static ref module_info:&'static str = "TLS MITM, to find non-secure x509 certs validation";
    static ref risk_type: u8            = utils::consts::RISK_TYPE_ENC;
    static ref domain_list:     Mutex<HashSet<String>>      = Mutex::new(HashSet::new());
    static ref domain_failed:  Mutex<HashMap<String, u8>>  = Mutex::new(HashMap::new());
}


pub fn run(CONF_TLS_MITM_DOMAIN: &Vec<toml::Value>, CONF_TLS_MITM_LISTEN: &str, db_tx: mpsc::Sender<String>) {
    if CONF_TLS_MITM_DOMAIN.len() == 0 {
        return
    }

    *domain_list.lock().unwrap() = config::parse_MITM_Domain_Array(CONF_TLS_MITM_DOMAIN);
    let listener = match net::TcpListener::bind(&CONF_TLS_MITM_LISTEN){
        Ok(listener) => listener,
        Err(err) => {
            error!("Failed to bind [{}], {}", &CONF_TLS_MITM_LISTEN, err);
            return;
        }
    };

    let port = CONF_TLS_MITM_LISTEN.split(':').collect::<Vec<&str>>();
    let port = if port.len() > 1 { port[1] } else { return };

    Command::new("sh").arg("-c")
                      .arg("iptables -t nat -N CYLONS_TLS_MITM 2>/dev/null;\
                            iptables -t nat -F CYLONS_TLS_MITM 2>/dev/null;\
                            iptables -t nat -D PREROUTING -p tcp -m multiport --dports 443,8443 -j CYLONS_TLS_MITM 2>/dev/null;\
                            iptables -t nat -A PREROUTING -p tcp -m multiport --dports 443,8443 -j CYLONS_TLS_MITM 2>/dev/null;").output();

    // #TODO compile global filter to bpf and apply it here, use pcap::compile
    match Command::new("iptables").args(&["-t", "nat", "-A", "CYLONS_TLS_MITM", "-p", "tcp",
                                            "-j", "REDIRECT", "--to-ports", &format!("{}", port)]).output() {
        Ok(out) if out.status.success() => {
            debug!("iptables REDIRECT success");
        },
        Ok(out) => {
            error!("iptables REDIRECT return: {}", out.status);
            io::stdout().write_all(&out.stdout).unwrap();
            io::stderr().write_all(&out.stderr).unwrap();
            return;
        },
        Err(err) => {
            error!("Failed to run iptables command, {}", err);
            return;
        }
    }

    for stream in listener.incoming() {
        let db_tx = db_tx.clone();
        thread::spawn(move||{
            handle_connection(stream.unwrap(), db_tx);
        });
    }
}

pub fn handle_connection(local_stream: net::TcpStream, db_tx: mpsc::Sender<String>) {
    // get SNI from ClientHello
    let SNI: String;
    let IP = local_stream.peer_addr().unwrap().ip();
    let mut buf = vec![0u8; 8192];
    let mut local_stream = local_stream.try_clone().unwrap();
    let len = local_stream.peek(&mut buf).unwrap();
    let(_remain, record) = match tls_parser::parse_tls_plaintext(&buf[..len]) {
        Ok((_remain, record)) => (_remain, record),
        Err(Err::Incomplete(_err)) => {
            //debug!("Defragmentation required (TLS record), {:?}", _err);
            return;
        }
        Err(err) => {
            error!("error parsing record, {:?}", err);
            return;
        },
    };

    match record.hdr.record_type {
        // handshake
        tls_parser::TlsRecordType::Handshake => {
            match &record.msg[0] {
                // client hello
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(data)) => {
                    let ext = tls_extensions::parse_tls_extensions(data.ext.unwrap()).unwrap();
                    SNI = if let Some(value) = get_sni(&ext.1) {
                            value
                        }
                        else {
                            "NOSNI".into()
                        };
                },
                // server hello
                _ => return
            }
        },
        // non handshake
        _ => return,
    };

    let destination = match utils::raw_socket::get_original_dst(local_stream.as_raw_fd()){
            Ok((addr, port)) => {
                if SNI == "NOSNI"{
                    format!("{}:{}", addr, port)
                }
                else{
                    format!("{}:{}", SNI, port)
                }
            },
            Err(err) => {
                error!("TLS ClientHello no SNI and failed to parse original dst, {}", err);
                return;
            }
    };
    let domain_list_lock = domain_list.lock().unwrap();
    let do_mitm = (domain_list_lock.contains("*") || domain_list_lock.contains(&SNI))   // not in MITM list, we will do SNI proxy
                    && SNI != "NOSNI"                               // no sni, we will do transparent proxy
                    && match domain_failed.lock().unwrap().get(&destination) {
                            Some(v) if v > &3 => false,              // MITM Failed more than 3 times
                            _ => true,
                        };
    drop(domain_list_lock);

    if do_mitm {
        debug!("MITM: [{}]", &destination);
//        let (info, risk_level) = match do_tls_mitm_rustls(&mut local_stream, &SNI, &destination){
        let (info, risk_level) = match do_tls_mitm_openssl(&mut local_stream, &SNI, &destination){
            // MITM SUCCESS
            Ok(_) => {
                domain_failed.lock().unwrap().insert(destination.to_owned(), 255);         // 0: MITM SUCCESS, will do it again; 255: MITM SUCCESS, will not MITM again
                (format!("MITM SUCCESS: [{}]", &destination), utils::consts::RISK_LEVEL_HIGH)
            },

            // MITM FAILED
            Err(e) => {
                let mut domain_failed_lock = domain_failed.lock().unwrap();
                match domain_failed_lock.get_mut(&destination) {
                    Some(v) => {
                        let _v = v.to_owned();
                        domain_failed_lock.insert(destination.to_owned(), _v + 1)
                    },
                    None => domain_failed_lock.insert(destination.to_owned(), 1),
                };
                drop(domain_failed_lock);
                (format!("MITM Failed: [{}], {}", &destination, e), utils::consts::RISK_LEVEL_LOG)
            },
        };

        info!("{}", info);
        db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )",
                        utils::get_unix_time(), utils::get_formatted_time(), IP, *module_type, *module_name,
                        *module_info, *risk_type, risk_level, info.replace("'", "''") )).unwrap();
    }
    else {
        debug!("Proxy: [{}]", &destination);
        do_sni_proxy(&mut local_stream, &destination);
    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
pub fn do_tls_mitm_openssl(stream: &mut net::TcpStream, SNI: &str, destination: &str) -> Result<(), Box<dyn Error>>{
    let (cert, key) = gen_certs_for_openssl(SNI)?;
    let mut acceptor = ssl::SslAcceptor::mozilla_intermediate(ssl::SslMethod::tls())?;
    acceptor.set_private_key(&key)?;
    acceptor.set_certificate(&cert)?;
    let ssl_stream = acceptor.build().accept(stream.try_clone()?)?;
    //ssl_stream.write(&b"HTTP/1.1 200 OK\r\n\r\nCylons TLS MITM\r\n".to_vec());

    let _SNI = SNI.to_owned();
    let _dest = destination.to_owned();
    thread::spawn(||{
        do_mitm_proxy(ssl_stream, _SNI, _dest);
    });
    Ok(())
}

#[allow(dead_code)]
#[allow(unused_variables)]
pub fn do_tls_mitm_rustls(stream: &mut net::TcpStream, SNI: &str, destination: &str) -> Result<(), Box<dyn Error>>{
    let mut conf = ServerConfig::new(rustls::NoClientAuth::new());
    let (certs, key) = gen_certs_for_rustls(SNI)?;
    conf.set_single_cert(certs, key)?;

    conf.set_protocols(&[b"http/1.1".to_vec()]);
    let mut server = ServerSession::new(&Arc::new(conf));
    let mut buf = vec![0u8; 8192];
    loop {
        while server.wants_write() {
            server.write_tls(stream)?;
        }

        if server.wants_read() {
            match server.read_tls(stream){
                Ok(size) if size == 0 => return Err("socket closed".into()),
                Ok(size) => trace!("TLS read_tls size: {}", size),
                Err(err) => return Err(err.into()),
            };

            server.process_new_packets()?;
            let len = server.read(&mut buf)?;
            if len > 0 {
                //debug!("read len: {}, data: {:?}", len, String::from_utf8_lossy(&buf[..len]));
                #[allow(unused_must_use)]
                {
                    server.write(&b"HTTP/1.1 200 OK\r\n\r\nCylons TLS MITM\r\n".to_vec());
                    server.write_tls(stream);  // write the message to tls, and then quit
                    return Ok(());
                }
            }
        }
    }
}

pub fn get_sni(ext: &Vec<tls_extensions::TlsExtension>) -> Option<String> {
    for i in ext {
        if let tls_extensions::TlsExtension::SNI(value) = i {
            return Some(String::from_utf8_lossy(value[0].1).to_string());
        }
    }
    return None
}

/*
pub fn load_certs(filename: &str) -> std::io::Result<Vec<rustls::Certificate>> {
    let certfile = std::fs::File::open(filename)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("failed to open {}: {}", filename, e)))?;
    let mut reader = std::io::BufReader::new(certfile);

    pemfile::certs(&mut reader).map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "failed to load certificate"))
}

pub fn load_private_key(filename: &str) -> std::io::Result<rustls::PrivateKey> {
    let keyfile = std::fs::File::open(filename)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("failed to open {}: {}", filename, e)))?;
    let mut reader = std::io::BufReader::new(keyfile);

    let keys = pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "failed to load private key"))?;
    if keys.len() != 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "expected a single private key"));
    }
    Ok(keys[0].clone())
}

pub fn gen_certs(SNI: &str) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), Box<dyn Error>>{
    return match load_certs(&format!("/tmp/cylons/{}.crt", SNI)) {
        Ok(certs) => {
            match load_private_key(&format!("/tmp/cylons/{}.key", SNI)) {
                Ok(key) => Ok((certs, key)),
                Err(err) => Err(format!("Error generating certs for: [{}], {}", SNI, err).into())
            }
        },
        Err(err) => Err(format!("Error generating certs for: [{}], {}", SNI, err).into())
    };
}
*/

// generate certs using openssl
pub fn gen_certs_for_openssl(SNI: &str) -> Result<(X509, PKey<Private>), Box<dyn Error>>{
    let pkey = PKey::from_rsa(Rsa::generate(2048)?)?;

    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, SNI)?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    // not before 365 days ago, not after 365 days later
    builder.set_not_before(&Asn1Time::from_unix((utils::get_unix_time() - 31536000) as i64).unwrap())?;
    builder.set_not_after(&Asn1Time::from_unix((utils::get_unix_time() + 31536000) as i64).unwrap())?;
    builder.sign(&pkey, MessageDigest::sha256())?;

    // PEM
    //let cert = builder.build().to_pem()?;
    //let pkey = pkey.private_key_to_pem_pkcs8()?;

    // DER
    //let cert = builder.build().to_der()?;
    //let pkey = pkey.private_key_to_der()?;

    Ok((builder.build(), pkey))
}

pub fn gen_certs_for_rustls(SNI: &str) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), Box<dyn Error>>{
    let (cert, pkey) = gen_certs_for_openssl(SNI)?;

    let cert = cert.to_der()?;
    let pkey = pkey.private_key_to_der()?;

    let rustls_certs = vec![rustls::Certificate(cert)];
    let rustls_pkey = rustls::PrivateKey(pkey);
    Ok((rustls_certs, rustls_pkey))
}


pub fn do_mitm_proxy(local_stream: ssl::SslStream<net::TcpStream>, SNI: String, destination: String) -> Result<(), Box<dyn Error>>{
    let upstream = match net::TcpStream::connect(&destination) {
        Ok(upstream) => {
            let mut ssl_connector_builder = ssl::SslConnector::builder(ssl::SslMethod::tls())?;
            ssl_connector_builder.set_verify(ssl::SslVerifyMode::NONE);
            let ssl_connector = ssl_connector_builder.build();
            let ssl_stream = ssl_connector.connect(&SNI, upstream)?;
            ssl_stream
        },
        Err(err) => {
            error!("SNI Proxy: Failed to connect to: [{}], {}", destination, err);
            return Err(err.into())
        }
    };

    upstream.get_ref().set_nodelay(true);
    upstream.get_ref().set_nonblocking(true);
    local_stream.get_ref().set_nodelay(true);
    local_stream.get_ref().set_nonblocking(true);

    // #TODO use select/poll or async IO some day
    // SslStream does not impl trait Clone, thus we have to wrap it in Arc<Mutex> and loop
    // Refer: https://github.com/sfackler/rust-openssl/issues/6
    
    let upstream = Arc::new(Mutex::new(upstream));
    let local_stream = Arc::new(Mutex::new(local_stream));
    let _upstream = upstream.clone();
    let _local_stream = local_stream.clone();

    // download stream
    let _download = thread::spawn(move || {
        let mut would_block;
        let mut buf = vec![0u8; 8192];
        loop {
            would_block = match _upstream.lock().unwrap().read(&mut buf) {
                Ok(read_size) if read_size > 0 => {
                    match _local_stream.lock().unwrap().write(&buf[..read_size]){
                        Ok(_) => debug!("MITM Proxy ⇩⇩ : {}", String::from_utf8_lossy(&buf[..read_size])),
                        Err(e) => {
                            trace!("upstream write failed: {}", e);
                            break;
                        }
                    }
                    false
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
                _ => {
                    trace!("upstream write failed");
                    break;
                }
            };

            if would_block{
                thread::sleep(time::Duration::from_millis(150));
            }
        }
        _upstream.lock().unwrap().shutdown();
        _local_stream.lock().unwrap().shutdown();
    });

    // upload stream
    let _upload = thread::spawn(move || {
        let mut would_block;
        let mut buf = vec![0u8; 8192];
        loop{
            would_block = match local_stream.lock().unwrap().read(&mut buf) {
                Ok(size) if size > 0 => {
                    match upstream.lock().unwrap().write(&buf[..size]) {
                        Ok(_) => debug!("MITM Proxy ⇧⇧ : {}", String::from_utf8_lossy(&buf[..size])),
                        _ => {
                            trace!("upstream write failed");
                            break;
                        }
                    }
                    false
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
                _ => {
                    trace!("local_stream read failed");
                    break;
                }
            };

            if would_block{
                thread::sleep(time::Duration::from_millis(150));
            }
        }
        upstream.lock().unwrap().shutdown();
        local_stream.lock().unwrap().shutdown();
    });
    Ok(())
}

// it's actually a transparent proxy, cause we have done looking up the original dst of the stream
pub fn do_sni_proxy(local_stream: &mut net::TcpStream, destination: &str){
    let mut buf = vec![0u8; 8192];
    let len = local_stream.read(&mut buf).unwrap();
    let upstream = match net::TcpStream::connect(destination) {
        Ok(mut upstream) => {
            match upstream.write(&buf[..len]) {
                Ok(_) => (),
                _ => {
                    error!("SNI Proxy: Failed to send ClientHello");
                    return;
                }
            };
            upstream
        },
        Err(err) => {
            error!("SNI Proxy: Failed to connect to: [{}], {}", destination, err);
            return;
        }
    };

    upstream.set_nodelay(true);
    local_stream.set_nodelay(true);
    let mut upstream_read = upstream.try_clone().unwrap();
    let mut upstream_write = upstream.try_clone().unwrap();
    let mut local_stream_read = local_stream.try_clone().unwrap();
    let mut local_stream_write = local_stream.try_clone().unwrap();

    // download stream
    let _download = thread::spawn(move || {
        let mut index: usize = 0;
        let mut offset: usize;
        let mut encrypted: bool = false;
        let mut buf = vec![0u8; 8192];
        loop {
            index += match upstream_read.read(&mut buf[index..]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    break;
                }
            };

            if encrypted {
                local_stream_write.write(&buf[..index]).unwrap();
                index = 0;
                continue;
            }

            offset = 0;
            loop {
                match tls_parser::parse_tls_plaintext(&mut buf[offset..index]) {
                    Ok((remain, _record)) => {
                        // here we split the response stream into every single TLS record
                        let remain_len = remain.len();
                        /*
                        let is_certificate = match record.hdr.record_type {
                            tls_parser::TlsRecordType::Handshake => {
                                match &record.msg[0] {
                                    TlsMessage::Handshake(TlsMessageHandshake::Certificate(_data)) => {
                                        true
                                    },
                                    _ => false
                                }
                            },
                            // non handshake
                            _ => false,
                        };

                        if is_certificate {
                            debug!("Certificate: {:?}", &buf[offset .. index - remain_len]);
                        }
                        */

                        // let output: String = format!("{:?}", &_record.msg[0]);
                        // debug!("TLS response from [{}]: {}", SNI, &output[..output.find('{').unwrap_or_else(||output.len())]);

                        local_stream_write.write(&buf[offset .. index - remain_len]).unwrap();
                        offset = index - remain_len;
                    },
                    Err(Err::Incomplete(_err)) => {
                        //debug!("[{}], Defragmentation required (TLS record), {:?}", SNI, _err);
                        break;
                    },
                    Err(_err) => {
                        // debug!("TLS response from [{}]: Encrypted Data", SNI);
                        local_stream_write.write(&buf[offset..index]).unwrap();
                        offset = index;
                        encrypted = true;
                        break;
                    }
                };
            }
            buf.copy_within(offset .. index, 0);
            index = index - offset;
        }

        upstream_read.shutdown(net::Shutdown::Both);
        local_stream_write.shutdown(net::Shutdown::Both);
        trace!("Download stream exited...");
    });

    // upload stream
    let _upload = thread::spawn(move || {
        let mut index: usize;
        let mut buf = vec![0u8;  8192];
        loop {
            // from docs, size = 0 means EOF,
            // maybe we don't need to worry about TCP Keepalive here.
            index = match local_stream_read.read(&mut buf) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    trace!("local_stream read failed");
                    break;
                }
            };
            match upstream_write.write(&buf[..index]) {
                Ok(_) => (),
                _ => {
                    trace!("upstream write failed");
                    break;
                }
            };
        }
        upstream_write.shutdown(net::Shutdown::Both);
        local_stream_read.shutdown(net::Shutdown::Both);
        trace!("Upload stream exited...");
    });
}
