#![allow(non_snake_case)]
#![allow(unused_variables)]
use toml;
use std::collections::HashMap;
use crate::utils::ipv4_str_to_int;

#[derive(Debug, Clone)]
pub struct Action {
    pub reset: bool,
    pub fuzz: bool,
    pub inject: Option<(String, Vec<u8>)>          // (payload_pattern: String, payload_response: Vec<u8>)
}

// T: ip addr, u32
// K: port, u16
pub type HashTree<T,K> = HashMap <T, HashMap 
                                 <K, HashMap 
                                 <T, HashMap
                                 <K, Action>>>>;

#[derive(Debug)]
pub struct TcpRule {
    pub tree: HashTree<u32, u16>,
}
     
impl TcpRule {
    pub fn new(tcp_hijack: &toml::Value) -> TcpRule {
        let mut tree: HashTree<u32, u16> = HashTree::new();

        let mut map = HashMap::new();
        let mut mapp = HashMap::new();
        let mut mappp = HashMap::new();

        for i in tcp_hijack.as_array().unwrap(){
            let src = ipv4_str_to_int(i["src"].as_str().unwrap());
            let sport = ipv4_str_to_int(i["sport"].as_str().unwrap()) as u16;
            let dst = ipv4_str_to_int(i["dst"].as_str().unwrap());
            let dport = ipv4_str_to_int(i["dport"].as_str().unwrap()) as u16;

            let action = Action {
                reset: i["action"]["reset"].as_bool().unwrap(),
                fuzz: i["action"]["fuzz"].as_bool().unwrap(),
                inject: match i.as_table().unwrap().contains_key("inject") {
                    true => {
                        /*
                        let payload_pattern = i["inject"]["payload_pattern"].as_str().unwrap();
                        let mut payload_response: Vec<u8> = Vec::new();
                        for byte in i["inject"]["payload_response"].as_array().unwrap(){
                            payload_response.push(byte.as_integer().unwrap() as u8);
                        }
                        Some((payload_pattern.to_owned(), payload_response))
                        */

                        Some((
                                i["inject"]["payload_pattern"].as_str().unwrap().to_owned(), 
                                i["inject"]["payload_response"].as_array().unwrap().iter().map(|x|{
                                    x.as_integer().unwrap() as u8
                                }).collect()
                            ))
                    },
                    false => None
                }
            };

            if tree.contains_key(&src) {
                let map1 = tree.get_mut(&src).unwrap();
                if map1.contains_key(&sport) {
                    let map2 = map1.get_mut(&sport).unwrap();
                    if map2.contains_key(&dst) {
                        let map = map2.get_mut(&dst).unwrap();
                        map.insert(dport, action);
                    }
                    else {
                        map.clear(); map.insert(dport, action);
                        map2.insert(dst, map.to_owned());
                    }
                }
                else {
                    map.clear(); map.insert(dport, action);
                    mapp.clear(); mapp.insert(dst, map.to_owned());
                    map1.insert(sport, mapp.to_owned());
                }
            }
            else {
                map.clear(); map.insert(dport, action);
                mapp.clear(); mapp.insert(dst, map.to_owned());
                mappp.clear(); mappp.insert(sport, mapp.to_owned());
                tree.insert(src, mappp.to_owned());
            }
        }
        TcpRule{tree}
    }

    pub fn get_Action(&self, src:&[u8;4], sport:u16, dst:&[u8;4], dport:u16) -> Option<&Action> {
        if let Some(map) = self.tree.get(&0) {
            if let Some(map) = map.get(&0) {
                if let Some(map) = map.get(&0) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
                if let Some(map) = map.get(&u32::from_be_bytes(*dst)) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
            }
            if let Some(map) = map.get(&sport) {
                if let Some(map) = map.get(&0) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
                if let Some(map) = map.get(&u32::from_be_bytes(*dst)) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
            }
        } 

        if let Some(map) = self.tree.get(&u32::from_be_bytes(*src)) {
            if let Some(map) = map.get(&0) {
                if let Some(map) = map.get(&0) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
                if let Some(map) = map.get(&u32::from_be_bytes(*dst)) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
            }
            if let Some(map) = map.get(&sport) {
                if let Some(map) = map.get(&0) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
                if let Some(map) = map.get(&u32::from_be_bytes(*dst)) {
                    //if map.contains_key(&0) || map.contains_key(&dport) {return true;}
                    if let Some(action) = map.get(&0) { return Some(action) }
                    if let Some(action) = map.get(&dport) { return Some(action) }
                }
            }
        }
        
        //return false;
        return None;
    }

    pub fn _get_Action(&self, src:&[u8;4], sport:u16, dst:&[u8;4], dport:u16) -> Option<&Action> {
        let map = if let Some(map) = self.tree.get(&0) { map }
            else if let Some(map) = self.tree.get(&u32::from_be_bytes(*src)) { map }
            else { return None };


        let map = if let Some(map) = map.get(&0) { map }
            else if let Some(map) = map.get(&sport) { map }
            else { return None };

        let map = if let Some(map) = map.get(&0) { map }
            else if let Some(map) = map.get(&u32::from_be_bytes(*dst)) { map }
            else { return None };

        let action = if let Some(action) = map.get(&0) { action }
            else if let Some(action) = map.get(&dport) { action }
            else { return None };

        return Some(action)
    }

    pub fn get_Action6(&self, src:&[u8;16], sport:u16, dst:&[u8;16], dport:u16) -> Option<&Action> {
        None
    }
}

