#![allow(dead_code)]
extern crate sqlite;
use std::error::Error;
use crate::utils::consts;

pub struct DB {
    conn: sqlite::Connection,
}


impl DB {
    pub fn new (flag: bool) -> Result<DB, Box<dyn Error>>{
        let path = &*consts::DB_PATH.lock().unwrap();
        let conn = match flag {
            consts::DB_READ_WRITE => sqlite::open(path)?,
            consts::DB_READ_ONLY => sqlite::Connection::open_with_flags(path, sqlite::OpenFlags::new().set_read_only())?
        };

        if flag == consts::DB_READ_WRITE {
            conn.execute("PRAGMA journal_mode=WAL")?;
            DB::create_table(&conn)?;
            DB::start_transaction(&conn)?;
        }
        Ok(
            DB {
                conn: conn,
           }
        )
    }

    pub fn start_transaction(conn: &sqlite::Connection) -> Result<(), Box<dyn Error>> {     // disable AUTO_COMMIT by BEGIN an transaction
        conn.execute("BEGIN")?;
        Ok(())
    }

    pub fn commit(&self, close: bool) -> Result<(), Box<dyn Error>> {                // commit data and start new trans
        let sql = match close {
            true => "COMMIT",
            false => "COMMIT; BEGIN",
        };
        self.conn.execute(sql)?;
        Ok(())
    }


    pub fn close(&self) -> Result<(), Box<dyn Error>> {
        self.commit(true)?;
        Ok(())
    }

    /*
    pub fn insert_traffic(&self, _time:u64, src:&str, dst:&str, sport:u16, dport:u16, 
            protocol:&str, length:u32, parsed_info:&str) -> Result<(), Box<dyn Error>> {

        self.conn.execute(format!("insert into t_traffic values (null, {}, '{}', '{}', {}, {}, '{}', {}, '{}')", 
                _time, src, dst, sport, dport, protocol, length, parsed_info))?;
        Ok(())
    }

    pub fn insert_result(&self, _time:u64, ip:&str, mod_type:u8, mod_name:&str, mod_info:&str,
            risk_type:u8, risk_level:u8, result:&str, false_positive:u8) -> Result<(), Box<dyn Error>> {
        self.conn.execute(format!("insert into t_result values (null,{},'{}',{},'{}','{}',{},{},'{}',{})",
                _time, ip, mod_type, mod_name, mod_info, risk_type, risk_level, result, false_positive))?;
        Ok(())
    }
    */

    pub fn read_only_sql(&self, sql: &str) -> Result<sqlite::Cursor, Box<dyn Error>> {
        let cursor = self.conn.prepare(sql)?.cursor();
        Ok(cursor)
    }

    pub fn write_only_sql(&self, sql: &str) -> Result<(), Box<dyn Error>> {
        self.conn.execute(sql)?;
        Ok(())
    }

    pub fn create_table(conn: &sqlite::Connection) -> Result<(), Box<dyn Error>> {
        let mut success = true;
        let mut msg: String = String::new();
        conn.execute("create table t_traffic (
            id          integer primary key autoincrement,
            time        text,
            time_str    text,
            src         text,
            dst         text,
            sport       int,
            dport       int,
            protocol    text,
            length      int,
            parsed_info text
        )").unwrap_or_else(|_err|{
            if let Some(1) = _err.code {
                // table already existed
            }
            else {
                success = false;
                msg = format!("Error: create table t_traffic: {}", _err);
            }
        });
        if !success {
            return Err(msg.into())
        }

        conn.execute("create table t_result (
            id          integer primary key autoincrement,
            time        text,
            time_str    text,
            ip          text,
            module_type tinyint,
            module_name text,
            module_info text,
            risk_type   tinyint,
            risk_level  tinyint,
            result      text,
            false_positive  tinyint
        )").unwrap_or_else(|_err|{
            if let Some(1) = _err.code {
                // table already existed
            }
            else {
                success = false;
                msg = format!("Error: create table t_result: {}", _err);
            }
        });
        if !success {
            return Err(msg.into())
        }

        Ok(())
    }
}
