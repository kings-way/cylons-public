pub mod db;
pub use db::DB;
use std::sync::mpsc;

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error};

// we gather all the db write operations here, to avoid write lock collision
pub fn db_writer(db: DB, rx: mpsc::Receiver<String>) {
    for sql in rx {
        db.write_only_sql(&sql).unwrap_or_else(|_err|{
            error!("SQL Error: {}", sql);
        });
        db.commit(false).unwrap();
    };
}
