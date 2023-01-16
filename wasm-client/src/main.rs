//!
//! A client to connect to Keystone Enclave WebAssembly runtime
//!
//! Usage: wasm-client [OPTIONS]
//!
//! Options:
//!   -c, --connect <CONNECT>  Address: hostname:portnumber
//!   -p, --program <PROGRAM>  WASM bytecode program
//!   -a, --attestation        Remote attestation
//!   -s  --skip               Skip WASM bytecode sending
//!   -v, --verbose            Verbose mode
//!   -h, --help               Print help
//!   -V, --version            Print version
//!

// SPDX-License-Identifier: MIT
// Copyright (C) 2025 VTT Technical Research Centre of Finland Ltd

use clap::Parser;
use schannel_lib::*;
use std::io::{stdin, stdout, Result, Write};
use std::net::Shutdown;
use std::str;

use wasm_client::connect;
use wasm_client::parse;
use wasm_client::receive_reply;
use wasm_client::send_pubkey;
use wasm_client::send_wasm;
use wasm_client::Cli;

fn main() -> Result<()> {
    // Parse command-line options
    let cli = Cli::parse();
    let attestation_check = cli.attestation;
    let skip_wasm = cli.skip;
    let verbose = cli.verbose;

    // Process host address and WASM code comamnd-line options
    let (hostaddr, mut wasm_code) = match parse(&cli, verbose) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // Open a connection to a host proxy server
    let stream = match connect(&hostaddr, verbose) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // Generate ECDH-P384 private and public key
    let (sk, pk) = ecc_keypair_gen();

    // Send own Elliptic Curve public key to the server
    let _nonce = match send_pubkey(&stream, &pk, verbose) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // Receive server's public key and attestation report
    let (server_pk, attestation) = match receive_reply(&stream) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // TODO: Attestation report could be verified here
    if attestation_check {
        println!("Attestation report: {:02X?}", attestation);
        println!("Attestation check TBD");
    }

    // Generate AES128 cipher using client's private key and server's pubkey
    let cipher = match aes_cipher_gen(&sk, &server_pk) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // Send a WASM program.
    match send_wasm(&stream, &cipher, &mut wasm_code, verbose, skip_wasm) {
        Ok(v) => v,
        Err(e) => return Err(e),
    }

    // Read text messages from a console, send requests, and read replies
    loop {
        let mut text = String::new();
        println!("Please enter WASM function name and parameters (exit with 'q'): ");
        let _ = stdout().flush();
        stdin()
            .read_line(&mut text)
            .expect("Did not enter a correct string");
        if let Some('\n') = text.chars().next_back() {
            text.pop();
        }
        if let Some('\r') = text.chars().next_back() {
            text.pop();
        }
        println!("You typed: {}", text);
        let mut data = text.as_bytes().to_vec();
        let encrypted: Vec<u8> = match encrypt(&mut data, &cipher) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        match schannel_write(&stream, &mut encrypted.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "An error occurred, terminating connection with {}",
                    stream.peer_addr().unwrap()
                );
                stream.shutdown(Shutdown::Both).unwrap();
                return Err(e);
            }
        }

        if text.len() == 1 && text.eq("q") {
            break;
        }

        let mut received: Vec<u8> = match schannel_read(&stream) {
            Ok(v) => v,
            Err(e) => {
                println!("Read error");
                return Err(e);
            }
        };
        let ivec: Vec<u8> = decrypt(&mut received, &cipher).unwrap();
        let decmsg: &[u8] = &ivec;
        let s = match str::from_utf8(decmsg) {
            Ok(v) => v,
            Err(e) => {
                println!("Invalid UTF-8 sequence: {}", e);
                return Ok(()); // TODO: fix - e is Utf8Error - we need io::Error
            }
        };
        println!("result: {}", s);
    }

    println!("Terminated.");
    Ok(())
}
