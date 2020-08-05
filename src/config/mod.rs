#![allow(non_snake_case)]
extern crate log;
extern crate toml;

use std::fs;
use std::collections::{HashMap, HashSet};
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

pub mod tcp_rule;
use tcp_rule::TcpRule;

pub fn parse_DNS_Hijack (DNS_HIJACK: &toml::Value) -> HashMap<String, String> {
    // parse CONF_DNS_HIJACK into HashMap
    let mut CONF_DNS_HIJACK_MAP = HashMap::new();
    for i in DNS_HIJACK.as_array().unwrap(){
        CONF_DNS_HIJACK_MAP.insert(
            i["name"].as_str().unwrap().to_string(), 
            i["record"].as_str().unwrap().to_string());
    }
    CONF_DNS_HIJACK_MAP
}

pub fn parse_MITM_Domain_Array(DOMAINS: &Vec<toml::Value>) -> HashSet<String> {
    let mut ret: HashSet<String> = HashSet::new();
    for domain in DOMAINS {
        ret.insert(domain.as_str().unwrap().to_owned());
    }
    ret
}

pub fn parse_config() -> (HashMap<String, String>, TcpRule, toml::Value) {
    let args = std::env::args().collect::<Vec<String>>();
    let filepath = match args.len() >= 2 {
        true => std::path::PathBuf::from(&args[1]),
        _ => {
            let mut tmp = std::env::current_exe().unwrap();
            tmp.pop();
            tmp.push("cylons.toml");
            tmp
        }
    };

    let contents = fs::read_to_string(&filepath).unwrap_or_else(|err|{
        error!("Error:{} ({:?})", err, &filepath);
        std::process::exit(-1);
    });
    let TOML_CONFIG: toml::Value = contents.parse::<toml::Value>().unwrap();

    let RuleDNS = parse_DNS_Hijack(&TOML_CONFIG["dns_hijack"]);
    let RuleTCP = TcpRule::new(&TOML_CONFIG["tcp_hijack"]);
    (RuleDNS, RuleTCP, TOML_CONFIG.to_owned())
}
