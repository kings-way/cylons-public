#![allow(unused_imports)]
#![allow(non_upper_case_globals)]
extern crate log;
extern crate nom;
extern crate ureq;
extern crate openssl;
extern crate tls_parser;
extern crate lazy_static;
use lazy_static::lazy_static;

use nom::Err;
use std::thread;
use std::error::Error;
use std::io::{Read, Write};
use std::sync::{mpsc, Mutex};
use std::net::{TcpStream, Ipv4Addr, Ipv6Addr};
use tls_parser::{TlsMessage, TlsMessageHandshake, tls_extensions};
use openssl::ssl::{self, SslMethod, SslConnector, SslVerifyMode};
use log::{trace, debug, info, warn, error};

use crate::utils;

lazy_static! {
    static ref time_unix: u64           = utils::get_unix_time();
    static ref time_formatted: String   = utils::get_formatted_time();
    static ref module_type: u8          = utils::consts::MODULE_TYPE_PASSIVE;
    static ref module_name:&'static str = "TLS Check";
    static ref module_info:&'static str = "check for weak protocols or ciphers in TLS";
    static ref risk_type: u8            = utils::consts::RISK_TYPE_ENC;
    static ref risk_level: u8           = utils::consts::RISK_LEVEL_LOG;
    static ref src: Mutex<String>       = Mutex::new(String::new());
}

pub fn check(data: &[u8], CONF_SSLLAB_ENABLE: bool, db_tx: mpsc::Sender<String>) {
    let pkt = etherparse::PacketHeaders::from_ethernet_slice(data).unwrap();
    let data = pkt.payload;

    let(_remain, record) = match tls_parser::parse_tls_plaintext(&*data) {
        Ok((_remain, record)) => (_remain, record),
        Err(Err::Incomplete(err)) => {
            debug!("Defragmentation required (TLS record), {:?}", err);
            return;
        }
        Err(err) => {
            error!("error while parsing record, {:?}", err);
            return;
        },
    };
//    debug!("--------------------------------------");
    
    let versions;
    let mut ciphers = Vec::new();
    *src.lock().unwrap() = utils::src_dst_proto_from_IpHeader(&pkt.ip).0;

    match record.hdr.record_type {
        // handshake
        tls_parser::TlsRecordType::Handshake => {
            let info = match &record.msg[0] {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(data)) => {
                    let ext = tls_extensions::parse_tls_extensions(data.ext.unwrap()).unwrap();     // TODO data.ext == None
                    let SNI = get_sni(&ext.1, CONF_SSLLAB_ENABLE, &db_tx);
                    ciphers = get_Ciphers(&data.ciphers);
                    let sup_ver = get_supported_version(&ext.1);
                    versions = if sup_ver.is_empty() {format!("{}",data.version)} else {sup_ver.to_owned()};

                    format!("ClientHello\nVersion:{}\nSNI:{:?}\nSupportedVersion:{}\nSupportedCiphers:{:?}", 
                                data.version, SNI, sup_ver, ciphers).replace("'", "''")
                },
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(data)) => {
                    let ext = tls_extensions::parse_tls_extensions(data.ext.unwrap()).unwrap();     // TODO data.ext == None
                    ciphers.push(get_cipher_name(data.cipher));
                    let sup_ver = get_supported_version(&ext.1);
                    versions = if sup_ver.is_empty() {format!("{}",data.version)} else {sup_ver};
                    format!("ServerHello\nVersion:{}\nCipher:{:?}", versions, ciphers).replace("'", "''")
                },
                _ => return
            };
            
            check_weak_ciphers(&ciphers, &db_tx);
            check_weak_protocols(&versions, &db_tx);
            debug!("{}", info);
            db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )", 
                                *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                                *module_info, *risk_type, *risk_level, info )).unwrap();
        },
        // non handshake
        _ => (),
    }
}

pub fn get_Ciphers(ciphers: &Vec<tls_parser::TlsCipherSuiteID>) -> Vec<&str> {
    let mut ret: Vec<&str> = Vec::new();
    for i in ciphers {
        if let Some(ciphersuite) = i.get_ciphersuite() {
            ret.push(ciphersuite.name)
        }
    }
    ret
}


pub fn get_cipher_name(cipher: tls_parser::TlsCipherSuiteID) -> &'static str {
    match cipher.get_ciphersuite() {
        Some(ciphersuite) => ciphersuite.name,
        None => "Unknown Cipher Suite"
    }
}

pub fn get_sni(ext: &Vec<tls_extensions::TlsExtension>, CONF_SSLLAB_ENABLE: bool, db_tx: &mpsc::Sender<String>) -> String {
    let mut SNI = None;
    for i in ext {
        if let tls_extensions::TlsExtension::SNI(value) = i {
            SNI = Some(value);
            break;
        }

    }
    match SNI {
        Some(SNI) => {
            let domain = String::from_utf8_lossy(SNI[0].1).to_string();
            // Check Cert and call sslab API
            if utils::consts::TLS_SERVER_CHECKED.lock().unwrap().insert(domain.clone()) {
                let _db_tx = db_tx.clone();
                let _domain = domain.clone();
                thread::spawn(move || cert_check(&_domain, CONF_SSLLAB_ENABLE, _db_tx));
            }
            else {
                debug!("Cert Check already done for: [{}], skipping...", domain);
            }
            domain
        },
        None => "".to_owned()
    }
}

pub fn get_supported_version(ext: &Vec<tls_extensions::TlsExtension>) -> String {
    let mut sup_ver = None;
    for i in ext {
        if let tls_extensions::TlsExtension::SupportedVersions(value) = i {
            sup_ver = Some(value);
            break;
        }
    }
    match sup_ver {
        Some(ver) => {
           ver.iter().map(|x|format!("{} ",x)).collect::<String>().trim().to_owned()
        },
        None => "".to_owned()
    }
}

// https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)#Sensitive_data_transmitted_in_clear-text
// Check for weak ciphers at client side

pub fn check_weak_protocols(protocols: &str, db_tx: &mpsc::Sender<String>) {
    let _protocols = protocols.to_lowercase();
    if _protocols.contains("ssl30") ||
       _protocols.contains("tls10") ||
       _protocols.contains("tls11") {
            info!("Found Insecure TLS Version: {}", _protocols);
            db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, 'Insecure TLS Version: {}', 0 )", 
                                *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                                *module_info, *risk_type, utils::consts::RISK_LEVEL_LOW, _protocols)).unwrap();
    }
}

pub fn check_weak_ciphers(ciphers: &Vec<&str>, db_tx: &mpsc::Sender<String>){
    //TODO maybe we should parse different parts directly from struct 'TlsCipherSuite'
    let mut result: Vec<String> = Vec::with_capacity(ciphers.len());

    for cipher in ciphers {
        let _cipher = cipher.to_lowercase();
        if _cipher.contains("rc4")  || 
           _cipher.contains("md5")  ||
           _cipher.contains("_des") 
//           _cipher.ends_with("sha") || _cipher.ends_with("sha1") 
        {
            result.push(_cipher);
        }
    }

    if result.len() > 0 {
        info!("Found Insecure TLS CipherSuite: {:?}", result);
        db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, 'Insecure TLS CipherSuite: {:?}', 0 )", 
                            *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                            *module_info, *risk_type, utils::consts::RISK_LEVEL_LOW, ciphers)).unwrap();
    }
}


pub fn do_cert_check(domain: &str) -> Result<(), Box<dyn Error>>{
    let mut ssl_connector_builder = SslConnector::builder(SslMethod::tls())?;
    ssl_connector_builder.set_verify(SslVerifyMode::PEER);

    let ssl_connector = ssl_connector_builder.build();
    let tcp_stream = TcpStream::connect(format!("{}:443",domain))?;
    match ssl_connector.connect(domain, tcp_stream){
        Ok(_) => Ok(()),
        Err(ssl::HandshakeError::Failure(err)) => {
            Err(err.ssl().verify_result().error_string().into())
        },
        _ => Err("Other error".into())
    }

}


pub fn cert_check (domain: &str, CONF_SSLLAB_ENABLE: bool, db_tx: mpsc::Sender<String>){
    let (cert_result, level) = match do_cert_check(domain) {
        Ok(_) => {
            debug!("======== Domain: [{}] Cert Verify ok ========", domain);
            ("OK".to_owned(), utils::consts::RISK_LEVEL_LOG)
        },
        Err(err) => {
            debug!("======== Domain: [{}] Cert Verity failed: {} ========", domain, err);
            (err.to_string(), utils::consts::RISK_LEVEL_MEDIUM)
        }
    };

    let ssllabs_result = match CONF_SSLLAB_ENABLE {
        true => match ssllabs_submit(domain) {
                    Ok(_) => "OK".to_owned(),
                    Err(err) => err
                },
        false => "DISABLED IN CONF".to_owned()
    };

    let result = format!("Domain: [{}]; Cert Verify: {}; SSLLabs submit: {}", domain, cert_result, ssllabs_result);
    db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )", 
                        *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                        *module_info, *risk_type, level, result)).unwrap();
}

/*
pub fn ssllabs_submit(_domain: &str) {
    let mut ssl_connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl_connector_builder.set_verify(SslVerifyMode::PEER);

    let ssl_connector = ssl_connector_builder.build();
    let tcp_stream = TcpStream::connect("api.ssllabs.com:443").unwrap();
    tcp_stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    match ssl_connector.connect("api.ssllabs.com", tcp_stream){
        Ok(mut stream) => {
            let request = format!("GET /api/v3/analyze?host={}&publish=on HTTP/1.1\r\nHost: api.ssllabs.com\r\n\r\n", _domain);
            stream.write_all(&Vec::from(request)).unwrap_or_else(|err|error!("SSL Labs submit error: {}", err));
            let mut res = vec![];
            stream.read_to_end(&mut res).unwrap_or_else(|err| {error!("SSL Labs submit error: {}", err); 0 });
            debug!("SSL Labs submit result: {}", String::from_utf8_lossy(&res));
        },
        Err(err) => error!("SSL Labs submit error: {}", err),
    }
}
*/

pub fn ssllabs_submit(_domain: &str) -> Result<(), String>{
    let rep = ureq::get("https://api.ssllabs.com/api/v3/analyze")
                    .query("host", _domain)
                    .query("publish", "on")
                    .call();
    if rep.ok() {
        debug!("SSL Labs submit result: {}", rep.into_string().unwrap_or_else(|err|err.to_string()));
        Ok(())
    }
    else {
        error!("SSL Labs submit error: {}", rep.status_line());
        Err(rep.status_line().to_owned())
    }
}
