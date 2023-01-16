//! Load Keystone Enclave WebAssembly runtime
//!
//! Usage: wasm-host [OPTIONS]
//!
//! Options:
//!   -e, --eapp <EAPP>        Enclave application
//!   -r, --runtime <RUNTIME>  Enclave runtime
//!   -l, --loader <LOADER>    Loader
//!   -a, --address <ADDRESS>  Listening address [default: 0.0.0.0:3333]
//!   -v, --verbose            Verbose mode
//!   -h, --help               Print help
//!   -V, --version            Print version
//!

// SPDX-License-Identifier: MIT
// Copyright (C) 2025 VTT Technical Research Centre of Finland Ltd

extern crate happ;
extern crate lazy_static;
extern crate std;

use clap::Parser;

use std::net::TcpListener;
use std::thread;

use wasm_host::handle_client;
use wasm_host::next_slot_index;
use wasm_host::parse;
use wasm_host::Cli;

/// Start a server listening to incoming connections and build an enclave
/// supporting secure channel from the enclave to the client for each
/// connection.
fn main() -> Result<(), std::io::Error> {
    let cli = Cli::parse();
    let verbose = cli.verbose;
    let (app, ert, ldr, address) = match parse(&cli, verbose) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let listener = match TcpListener::bind(&address) {
        Ok(listener) => listener,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("Failed to bind to address {}: {}", address, e),
            ));
        }
    };
    println!("Server listening on {}", &address);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = stream
                    .peer_addr()
                    .map(|addr| println!("New connection: {}", addr))
                {
                    println!("Failed to get peer address: {}", e);
                }
                let enclave_app = app.clone();
                let runtime = ert.clone();
                let loader = ldr.clone();
                match next_slot_index() {
                    Ok(index) => {
                        thread::spawn(move || {
                            if let Err(e) =
                                handle_client(stream, enclave_app, runtime, loader, index)
                            {
                                println!("Error in handle_client: {} ", e as u32);
                            }
                        });
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    Ok(())
}
