//! Test-support fakes for the Lab failure-injection suite (FM-741): a
//! stateful fake Proxmox VE and a restartable Lab controller over one
//! SQLite file.
#![allow(dead_code)]

pub mod fake_pve;
pub mod lab_controller;
