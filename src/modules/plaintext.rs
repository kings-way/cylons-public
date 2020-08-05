#![allow(non_upper_case_globals)]
extern crate regex;
extern crate libflate;
extern crate etherparse;
extern crate lazy_static;

use regex::Regex;
use std::io::Read;
use libflate::gzip;
use std::error::Error;
use lazy_static::lazy_static;
use std::sync::{Arc, mpsc, Mutex};
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

use crate::utils::{self, consts};

const WORDS_MIN_LEN: usize       = 4;
const DICT_WORDS_MIN_COUNT: usize= 4;
const WORDS_COUNT_ENDLESS: usize = 0;
const FIND_SINGLE_WORD: bool     = true;
const FIND_STRINGS: bool         = false;

lazy_static! {
    static ref time_unix: u64           = utils::get_unix_time();
    static ref time_formatted: String   = utils::get_formatted_time();
    static ref module_type: u8          = utils::consts::MODULE_TYPE_PASSIVE;
    static ref module_name:&'static str = "Plaintext Check";
    static ref module_info:&'static str = "check for plaintext traffic";
    static ref risk_type: u8            = utils::consts::RISK_TYPE_ENC;
    static ref risk_level: u8           = utils::consts::RISK_LEVEL_LOW;
    static ref src: Mutex<String>       = Mutex::new(String::new());

    static ref module_name2:&'static str= "Sensitive Text Check";
    static ref module_info2:&'static str= "check for sensitive text in plaintext";
    static ref risk_type2: u8           = utils::consts::RISK_TYPE_SENSI;
    static ref risk_level2: u8          = utils::consts::RISK_LEVEL_MEDIUM;
}

pub fn check(data: &[u8], SENSITIVE_RE: Arc<Regex>, db_tx: mpsc::Sender<String>) {
    let pkt = etherparse::PacketHeaders::from_ethernet_slice(data).unwrap();
    if pkt.payload.len() == 0 { return };
    *src.lock().unwrap() = utils::src_dst_proto_from_IpHeader(&pkt.ip).0;
    let payload = match check_http_gzip(&pkt.payload){
        Some(data) => {
//            debug!("HTTP GZIP Decode After: {}", String::from_utf8_lossy(&data));
            data
        },
        None => pkt.payload.to_vec()
    };

    let (continuous_chars, all_ascii) = get_strings(&payload, WORDS_MIN_LEN, WORDS_COUNT_ENDLESS, FIND_SINGLE_WORD);

    let mut words_in_dict: Vec<&str> = Vec::with_capacity(continuous_chars.len());
    let mut words_in_dict_chars_count = 0;

    let mut dict_match_result: bool = false;
    if !all_ascii {
        for i in continuous_chars {
            if consts::ENGLISH_DICT.contains(i.to_lowercase().as_str()) {
                words_in_dict.push(i);
                words_in_dict_chars_count += i.len();
            }
            // if there are more than 4 meaningful words, or these words has more than 12 letters
            // or if there are more than 10 continuous words 
            if words_in_dict.len() > DICT_WORDS_MIN_COUNT || words_in_dict_chars_count > (DICT_WORDS_MIN_COUNT + 1) * WORDS_MIN_LEN {
                dict_match_result = true;
                break;
            }
        }
    }
    if all_ascii || dict_match_result {
        let result = format!("Plaintext: {:?}", &get_strings(&payload, WORDS_MIN_LEN, WORDS_COUNT_ENDLESS, FIND_STRINGS).0).replace("'", "''");
        //debug!("{:.150}", result);
        debug!("all_ascii: {}, words_in_dict: {:?}, {}", all_ascii, words_in_dict, result);
        db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )", 
                            *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name,
                            *module_info, *risk_type, *risk_level, result )).unwrap();
        sensitive_scan(&payload, SENSITIVE_RE, db_tx);
    }
}

pub fn sensitive_scan(payload: &[u8], SENSITIVE_RE: Arc<Regex>, db_tx: mpsc::Sender<String>) {
    let mut ret: Vec<String> = Vec::new();
    let mut found_keywords = Vec::new();
    let data = String::from_utf8_lossy(payload);
    let data = data.trim();
    for i in SENSITIVE_RE.find_iter(&data) {
        if found_keywords.contains(&i.as_str()) {
            continue
        }
        found_keywords.push(i.as_str());
        ret.push(format!("[{}] in [{}]", i.as_str(), &data));
    }
    if ret.len() > 0 {
        let result = format!("Sensitive Data: {:?}", ret).replace("'", "''");
        debug!("{:.150}", result);
        db_tx.send(format!("insert into t_result values(null, '{}', '{}', '{}', {}, '{}', '{}', {}, {}, '{}', 0 )", 
                            *time_unix, *time_formatted, *src.lock().unwrap(), *module_type, *module_name2,
                            *module_info2, *risk_type2, *risk_level2, result )).unwrap();
    }
}


pub fn check_http_gzip(data: &[u8]) -> Option<Vec<u8>>{
    // content-encoding: gzip
    // TODO content-encoding: br
    if String::from_utf8_lossy(data).to_lowercase().contains("content-encoding: gzip") {
        // we just search for the magic number of gzip, instead of parsing the http header.
        // crate 'httparse' does not offer 'http body', only returns offset of the end of header, not the start of body)
        let mut index = 0;
        let data_len = data.len();
        while index < data_len {
            if data[index] == 0x1f && data[index+1] == 0x8b {
                break;
            }
            else {
                index += 1;
            }
        }
        // found the magic
        if index != data_len {
            let mut header = vec![0u8;index];
            header.copy_from_slice(&data[..index]);

            match gzip_uncompress(&data[index..]) {
                Ok(body) => {
                    header.extend(body);
                    return Some(header);
                },
                Err(err) => {
                    error!("http gzip decode: {}; Maybe chunked ?", err);
                    return None;
                }
            }
        }
    }

    return None;
}


pub fn gzip_uncompress(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>{
    // TODO fix: this crate will fail if input data is not complete
    let mut ret = Vec::new();
    let mut decoder = gzip::Decoder::new(data)?;
    decoder.read_to_end(&mut ret)?;
    Ok(ret)
}

// just care for ascii chars for now
// we may choose unicode_segmentation::UnicodeSegmentation to parse utf8 chars in the future

pub fn get_strings(data: &Vec<u8>, len_min: usize, count_max: usize, words: bool) -> (Vec<&str>, bool){
    let mut ret = Vec::with_capacity(data.len() / len_min);
    let data_len = data.len();

    let mut start: usize;
    let mut index: usize = 0;
    let mut count: usize = 0;
    let mut all_ascii = true;

    while index < data_len {
        start = index;
        while index < data_len {
            if words && data[index].is_ascii_alphanumeric() ||          // single word
                !words && data[index] >= 32 && data[index] <= 126       // strings may contain spaces and punctuations
            {
                index += 1;
            }
            else {
                if data[index] == 0 || data[index] > 126 {
                    all_ascii = false;
                }
                if (index - start) >= len_min {
                    ret.push(unsafe{std::str::from_utf8_unchecked(&data[start..index])});
                    count += 1;
                }
                break;
            }
        }

        if count_max > 0 && count >= count_max {
            break;
        }
        index += 1;
    }

    // for all ascii data, we return the whole string
    if all_ascii && !words{
        ret.clear();
        ret.push(unsafe{std::str::from_utf8_unchecked(&data)})
    }

    (ret, all_ascii)
}
