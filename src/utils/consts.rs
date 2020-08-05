#![allow(dead_code)]
extern crate log;
extern crate lazy_static;
use lazy_static::lazy_static;

use std::sync::Mutex;
use std::iter::FromIterator;
use std::collections::{HashSet,HashMap};
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

lazy_static! {
    pub static ref DB_PATH: Mutex<String>       = Mutex::new(String::new());
}

pub const DB_READ_ONLY:  bool = true;
pub const DB_READ_WRITE: bool = false;

pub const MODULE_TYPE_ACTIVE : u8 = 0;
pub const MODULE_TYPE_PASSIVE: u8 = 1;

pub const RISK_LEVEL_CRITICAL: u8 = 0;
pub const RISK_LEVEL_HIGH    : u8 = 1;
pub const RISK_LEVEL_MEDIUM  : u8 = 2;
pub const RISK_LEVEL_LOW     : u8 = 3;
pub const RISK_LEVEL_LOG     : u8 = 255;

// TODO
pub const RISK_TYPE_ENC     : u8 = 0;       // encryption or plaintext
pub const RISK_TYPE_AUTH    : u8 = 1;       // authentication 
pub const RISK_TYPE_SENSI   : u8 = 2;       // sensitive data
pub const RISK_TYPE_OTHER   : u8 = 254;
pub const RISK_TYPE_NONE    : u8 = 255;

// https://en.wikipedia.org/wiki/EtherType
lazy_static! {
    pub static ref ETH_PROTOCOL: HashMap<u16, &'static str> = {
        let mut map = HashMap::with_capacity(100);
        map.insert(0x0800, "Internet Protocol version 4 (IPv4)");
        map.insert(0x0806, "Address Resolution Protocol (ARP)");
        map.insert(0x0842, "Wake-on-LAN[9]");
        map.insert(0x22F0, "Audio Video Transport Protocol (AVTP)");
        map.insert(0x22F3, "IETF TRILL Protocol");
        map.insert(0x22EA, "Stream Reservation Protocol");
        map.insert(0x6002, "DEC MOP RC");
        map.insert(0x6003, "DECnet Phase IV, DNA Routing");
        map.insert(0x6004, "DEC LAT");
        map.insert(0x8035, "Reverse Address Resolution Protocol (RARP)");
        map.insert(0x809B, "AppleTalk (Ethertalk)");
        map.insert(0x80F3, "AppleTalk Address Resolution Protocol (AARP)");
        map.insert(0x8100, "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[10]");
        map.insert(0x8102, "Simple Loop Prevention Protocol (SLPP)");
        map.insert(0x8103, "Virtual Link Aggregation Control Protocol (VLACP)");
        map.insert(0x8137, "IPX");
        map.insert(0x8204, "QNX Qnet");
        map.insert(0x86DD, "Internet Protocol Version 6 (IPv6)");
        map.insert(0x8808, "Ethernet flow control");
        map.insert(0x8809, "Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol (LACP)");
        map.insert(0x8819, "CobraNet");
        map.insert(0x8847, "MPLS unicast");
        map.insert(0x8848, "MPLS multicast");
        map.insert(0x8863, "PPPoE Discovery Stage");
        map.insert(0x8864, "PPPoE Session Stage");
        map.insert(0x887B, "HomePlug 1.0 MME");
        map.insert(0x888E, "EAP over LAN (IEEE 802.1X)");
        map.insert(0x8892, "PROFINET Protocol");
        map.insert(0x889A, "HyperSCSI (SCSI over Ethernet)");
        map.insert(0x88A2, "ATA over Ethernet");
        map.insert(0x88A4, "EtherCAT Protocol");
        map.insert(0x88A8, "Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel.");
        map.insert(0x88AB, "Ethernet Powerlink[citation needed]");
        map.insert(0x88B8, "GOOSE (Generic Object Oriented Substation event)");
        map.insert(0x88B9, "GSE (Generic Substation Events) Management Services");
        map.insert(0x88BA, "SV (Sampled Value Transmission)");
        map.insert(0x88BF, "MikroTik RoMON (unofficial)");
        map.insert(0x88CC, "Link Layer Discovery Protocol (LLDP)");
        map.insert(0x88CD, "SERCOS III");
        map.insert(0x88DC, "WSMP, WAVE Short Message Protocol");
        map.insert(0x88E3, "Media Redundancy Protocol (IEC62439-2)");
        map.insert(0x88E5, "MAC security (IEEE 802.1AE)");
        map.insert(0x88E7, "Provider Backbone Bridges (PBB) (IEEE 802.1ah)");
        map.insert(0x88F7, "Precision Time Protocol over IEEE 802.3 Ethernet");
        map.insert(0x88F8, "NC-SI");
        map.insert(0x88FB, "Parallel Redundancy Protocol (PRP)");
        map.insert(0x8902, "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)");
        map.insert(0x8906, "Fibre Channel over Ethernet (FCoE)");
        map.insert(0x8914, "FCoE Initialization Protocol");
        map.insert(0x8915, "RDMA over Converged Ethernet (RoCE)");
        map.insert(0x891D, "TTEthernet Protocol Control Frame (TTE)");
        map.insert(0x892F, "High-availability Seamless Redundancy (HSR)");
        map.insert(0x9000, "Ethernet Configuration Testing Protocol[12]");
        map.insert(0x9100, "VLAN-tagged (IEEE 802.1Q) frame with double tagging");
        map.insert(0xF1C1, "Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)");
        map
    };
}

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
pub const IP_PROTOCOL: [&str; 143] =
                ["HOPOPT", "ICMP", "IGMP", "GGP", "IPv4", "ST", "TCP", "CBT", "EGP", 
                 "IGP","BBN-RCC-MON", "NVP-II", "PUP", "ARGUS (deprecated)", "EMCON", 
                 "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP", "PRM", "XNS-IDP", 
                 "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", 
                 "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP", "DDP", 
                 "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", 
                 "IDRP", "RSVP", "GRE", "DSR", "BNA", "ESP", "AH", "I-NLSP", "SWIPE (deprecated)", 
                 "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts", 
                 "any host internal protocol", "CFTP", "any local network", "SAT-EXPAK", 
                 "KRYPTOLAN", "RVD", "IPPC", "any distributed file system", "SAT-MON", 
                 "VISA", "IPCV", "CPNX", "CPHB", "WSN", "PVP", "BR-SAT-MON", "SUN-ND", 
                 "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP or IPTM", 
                 "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPFIGP", "Sprite-RPC", "LARP", 
                 "MTP", "AX.25", "IPIP", "MICP (deprecated)", "SCC-SP", "ETHERIP", "ENCAP", 
                 "any private encryption scheme", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", 
                 "SCPS", "QNX", "A/N", "IPComp", "SNP", "Compaq-Peer", "IPX-in-IP", "VRRP", 
                 "PGM", "any 0-hop protocol", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", 
                 "SMP", "SM (deprecated)", "PTP", "ISIS over IPv4", "FIRE", "CRTP", "CRUDP", 
                 "SSCOPMCE", "IPLT", "SPS", "PIPE", "SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility Header", 
                 "UDPLite", "MPLS-in-IP", "manet", "HIP", "Shim6", "WESP", "ROHC"];


//pub const _TLS_ALERT_LEVEL: [&str;3] = ["Unknown Level", "Warning", "Fatal"];

// https://techcommunity.microsoft.com/t5/IIS-Support-Blog/SSL-TLS-Alert-Protocol-and-the-Alert-Codes/ba-p/377132
lazy_static! {
    pub static ref TLS_ALERT_LEVEL: HashMap<u8, &'static str> = {
        let mut map = HashMap::with_capacity(5);
        map.insert(1, "Warning");
        map.insert(2, "Fatal");
        map.insert(255, "Unknown Level");
        map
    };
}

lazy_static! {
    pub static ref TLS_ALERT_DESC: HashMap<u8, &'static str> = {
        let mut map = HashMap::with_capacity(50);
        map.insert(0,  "close_notify");
        map.insert(10, "unexpected_message");
        map.insert(20, "bad_record_mac");
        map.insert(21, "decryption_failed");
        map.insert(22, "record_overflow");
        map.insert(30, "decompression_failure");
        map.insert(40, "handshake_failure");
        map.insert(42, "bad_certificate");
        map.insert(43, "unsupported_certificate");
        map.insert(44, "certificate_revoked");
        map.insert(45, "certificate_expired");
        map.insert(46, "certificate_unknown");
        map.insert(47, "illegal_parameter");
        map.insert(48, "unknown_ca");
        map.insert(49, "access_denied");
        map.insert(50, "decode_error");
        map.insert(51, "decrypt_error");
        map.insert(60, "export_restriction");
        map.insert(70, "protocol_version");
        map.insert(71, "insufficient_security");
        map.insert(80, "internal_error");
        map.insert(90, "user_cancelled");
        map.insert(100, "no_renegotiation");
        map.insert(255, "unsupported_extension");
        map
    };
}

lazy_static! {
    pub static ref ENGLISH_DICT_TEXT: String = {
        let args = std::env::args().collect::<Vec<String>>();
        let mut filepath = match args.len() >= 2 {
            true => std::path::PathBuf::from(&args[1]),
            _ => std::env::current_exe().unwrap()
        };

        filepath.pop();
        filepath.push("words_alpha.txt");
        std::fs::read_to_string(&filepath).unwrap_or_else(|err|{
            error!("Error:{} ({:?})", err, &filepath);
            std::process::exit(-1);
        })
    };

    pub static ref ENGLISH_DICT: HashSet<&'static str> = {
        HashSet::from_iter(ENGLISH_DICT_TEXT.split_whitespace())
    };
}

lazy_static! {
    pub static ref TLS_SERVER_CHECKED: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}
