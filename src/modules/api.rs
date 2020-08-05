extern crate log;
extern crate rocket;
extern crate rocket_contrib;

use rocket::State;
use rocket_contrib::json::Json;
use std::sync::{mpsc, Mutex, mpsc::Receiver};
use rocket::config::{Config, Environment, LoggingLevel};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

use crate::database::DB;
use crate::utils::consts;

const DEFAULT_MAX_RESULT_COUNT:  usize = 10;
const DEFAULT_MAX_TRAFFIC_COUNT: usize = 30;

#[get("/")]
fn index() -> &'static str {
    "Hello, Cylons !"
}

#[get("/feed/result?<last_id>&<max_count>")]
fn feed_result(
                db_read: State<Mutex<DB>>,
                last_id: Option<usize>,
                max_count: Option<usize>
            ) -> Json<Vec<(usize, String, String, u8, String, String, u8, u8, String, u8)>> {

    let last_id = if let Some(value) = last_id { value } else { 0 };
    let max_count = if let Some(value) = max_count { value } else { DEFAULT_MAX_RESULT_COUNT };

    // pre-allocate limited memory
    let mut ret = Vec::with_capacity(if max_count > 1000 { 1000 } else { max_count });
    let db_read = db_read.lock().expect("Failed to acquire lock for 'db_read'");

    match db_read.read_only_sql(
                    &format!("select id,time_str,ip,module_type,module_name,module_info,
                                risk_type,risk_level,result,false_positive from t_result where id > {} limit {}",
                                last_id, max_count )) {
        Err(err) => error!("DB query error: {}", err),
        Ok(mut cursor) => {
            while let Some(row) = cursor.next().unwrap() {
                ret.push((
                        row[0].as_integer().unwrap() as usize,
                        row[1].as_string().unwrap().to_owned(),
                        row[2].as_string().unwrap().to_owned(),
                        row[3].as_integer().unwrap() as u8,
                        row[4].as_string().unwrap().to_owned(),
                        row[5].as_string().unwrap().to_owned(),
                        row[6].as_integer().unwrap() as u8,
                        row[7].as_integer().unwrap() as u8,
                        row[8].as_string().unwrap().to_owned(),
                        row[9].as_integer().unwrap() as u8
                    ));
            }
        }
    }
    drop(db_read);
    Json(ret)
}

#[get("/feed/traffic?<max_count>")]
fn feed_traffic(
                parsed_packet_rx: State<Mutex<Receiver<(String, String, u16, String, u16, String, u16, String)>>>,
                max_count: Option<usize>
            )  -> Json<Vec<(String, String, u16, String, u16, String, u16, String)>> {

    let max_count = if let Some(value) = max_count { value } else { DEFAULT_MAX_TRAFFIC_COUNT };
    // pre-allocate limited memory
    let mut ret = Vec::with_capacity(if max_count > 1000 { 1000 } else { max_count });
    let parsed_packet_rx = parsed_packet_rx.lock().expect("Failed to acquire lock for 'parsed_packet_rx'");
    for _ in 0..max_count {
        match parsed_packet_rx.try_recv() {
            Ok(value) => ret.push(value),
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => break,     // TODO on channel closed, how to exit?
        }
    }
    drop(parsed_packet_rx);
    Json(ret)
}


pub fn run(listen_addr: &str, parsed_packet_rx: mpsc::Receiver<(String, String, u16, String, u16, String, u16, String)>) {
    let _listen_addr: Vec<&str> = listen_addr.trim().split(":").collect();
    let (addr, port) = match _listen_addr.len() == 2 {
        true => (_listen_addr[0],  _listen_addr[1].parse::<u16>().unwrap()),
        false => {
            error!("api_listen_addr format error: {}, default to [127.0.0.1:8000] ", listen_addr);
            ("127.0.0.1", 8000)
        }
    };

    let config = Config::build(Environment::Production)
            .address(addr)
            .port(port)
            .log_level(LoggingLevel::Off)       // this does not help
            .finalize().unwrap();

    let db_read = DB::new(consts::DB_READ_ONLY).unwrap();         // read only db connection

    rocket::custom(config)
            .manage(Mutex::new(parsed_packet_rx))
            .manage(Mutex::new(db_read))
            .mount("/", routes![index])
            .mount("/api", routes![feed_traffic, feed_result])
            .launch();
}

