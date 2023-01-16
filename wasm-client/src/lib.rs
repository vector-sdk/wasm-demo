//! A small library that is used to establish secure channel between the nodes.
//!
//! # Features
//! - Send a connection request to a TCP stream with nonce and client public key
//! - Receive a message reply with a server public key and an attestation report
//!
//! # Dependencies
//! This library relies on the following crates:
//! - `static_dh_ecdh`: For Elliptic Diffie-Hellman key exchange
//! - `io`: For channel reading, writing, and error/status states
//! - `net`: For TCP/IP stream
//!

// SPDX-License-Identifier: MIT
// Copyright (C) 2025 VTT Technical Research Centre of Finland Ltd

use aes::Aes128;
use clap::Parser;
use rand::Rng;
use schannel_lib::{encrypt, schannel_read, schannel_write};
use static_dh_ecdh::ecdh::ecdh::FromBytes;
use static_dh_ecdh::ecdh::ecdh::PkP384;
use static_dh_ecdh::ecdh::ecdh::ToBytes;
use std::fs;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::{Shutdown, TcpStream};

#[derive(Parser, Debug)]
#[command(author, version)]
#[command(about = "Connect to Keystone Enclave WebAssembly runtime")]
pub struct Cli {
    /// Connection: hostname:portnumber
    #[clap(short, long)]
    connect: Option<String>,
    /// WASM bytecode program
    #[clap(short, long)]
    program: Option<String>,
    /// Remote attestation
    #[clap(short, long, default_value_t = false)]
    pub attestation: bool,
    /// Skip WASM bytecode sending
    #[clap(short, long, default_value_t = false)]
    pub skip: bool,
    /// Verbose mode
    #[clap(short, long, default_value_t = false)]
    pub verbose: bool,
}

/// Parse command-line options
///
/// Using Clap derive-mode to specify command-line
/// parameters. Parameters are specified in 'struct Cli'. Boolean
/// parameters are marked as public so that those can be directly
/// referred. Mandatory parameters conection address and WASM program
/// are checked. The function will return the connection address as a
/// string and WASM program as a byte vector or an error.
///
/// # Arguments
///
/// * `cli` - Command-line parameters as 'Clap' derived structure.
/// * `verbose` - Verbose mode setting
///
/// # Returns
///
/// This function returns the output of the command execution as a `Result`:
///
/// * `Ok`- Connection address and WASM program bytes are returned
/// * `Err` - Mandatory parameters are missing or file is not found
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If mandatory parameter, a connection address, is missing
/// * If mandatory parameter, a WASM program filename, is missing
/// * If WASM program file reading failed, e.g., file is not found
///
pub fn parse(cli: &Cli, verbose: bool) -> Result<(&String, Vec<u8>)> {
    let hostaddr = match &cli.connect {
        Some(name) => name,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Server address is missing",
            ));
        }
    };
    let filename = match &cli.program {
        Some(name) => name,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "WASM program filename is missing",
            ));
        }
    };

    // Read WebAssembly program from the file
    let wasm_code = match fs::read(filename) {
        Ok(v) => {
            if verbose {
                println!("WASM code read (length={})", v.len());
            }
            v
        }
        Err(e) => {
            println!("WASM code reading failed from {}", filename);
            return Err(e);
        }
    };
    Ok((hostaddr, wasm_code))
}

/// Receive a service reply from the schannel-host
///
/// Server's public key and an attestation report will be received.
///
/// # Arguments
///
/// * `stream` - TCP connection stream to a server
///
/// # Returns
///
/// The function returns the server public key and an attestation report:
///
/// * `Ok`- Contains a server public key and an attestation report
/// * `Err` - Error from TCP connection
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If there was an error when reading from a TCP stream
/// * If there was unexpected end of data
/// * If there was an error in the public key
///
pub fn receive_reply(mut stream: &TcpStream) -> Result<(PkP384, Vec<u8>)> {
    const MAX_MESSAGE_SIZE: usize = 512;
    let mut received: Vec<u8> = vec![];
    let mut attestation: Vec<u8> = vec![];
    let mut rx_bytes = [0u8; MAX_MESSAGE_SIZE];
    let mut total_bytes_read = 0;
    let mut pubkey_len = 0;

    loop {
        // Read from the current data in the TcpStream
        let bytes_read = match stream.read(&mut rx_bytes) {
            Ok(bytes_read) => bytes_read,
            Err(e) => {
                return Err(e);
            }
        };
        // println!("{} bytes read", bytes_read);
        total_bytes_read += bytes_read;

        if total_bytes_read == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "No data received"));
        }

        if pubkey_len == 0 && total_bytes_read > 0 {
            pubkey_len = rx_bytes[0] as usize;
        }

        if total_bytes_read >= pubkey_len + 1 {
            received.extend_from_slice(&rx_bytes[1..pubkey_len + 1]);
            attestation.extend_from_slice(&rx_bytes[pubkey_len + 1..bytes_read]);
        } else {
            received.extend_from_slice(&rx_bytes[..bytes_read]);
        }

        // If we didn't fill the array
        // stop reading because there's no more data (we hope!)
        if bytes_read < MAX_MESSAGE_SIZE {
            break;
        }
    }

    if received.len() < pubkey_len {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Incomplete public key received",
        ));
    }

    let pk: PkP384 = match PkP384::from_bytes(&received) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!(
                "Failed to parse public key from received data: {:02X?}",
                received
            );
            return Err(Error::new(ErrorKind::InvalidData, "Not a public key"));
        }
    };
    Ok((pk, attestation))
}

/// Establish a TCP connection to a WASM enclave host proxy
///
/// Create a connection and return a TCP strea,
///
/// # Arguments
///
/// * `hostaddr` - Connecting address in 'hostname:portnumber' format
/// * `verbose` - Verbose mode setting
///
/// # Returns
///
/// This function returns the output of the command execution as a `Result`:
///
/// * `Ok`- Connection stream is returned
/// * `Err` - Connection establishing failed
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * Connection to the remote host failed, e.g., no listening service
///
pub fn connect(hostaddr: &String, verbose: bool) -> Result<TcpStream> {
    let stream = match TcpStream::connect(&hostaddr) {
        Ok(v) => {
            if verbose {
                println!("Successfully connected to {}", hostaddr);
            }
            v
        }
        Err(e) => {
            println!("Connection to {} failed", hostaddr);
            return Err(e);
        }
    };
    Ok(stream)
}

/// Send client public key to a remote service
///
/// The request includes a nonce value and a public key of the client.
/// The size of the nonce is passed in the first byte.
///
/// # Arguments
///
/// * `stream` - TCP connection stream to a server
/// * `pk`- Client public key
/// * `verbose` - Verbose mode setting
///
/// # Returns
///
/// This function returns the output of the command execution as a `Result`:
///
/// * `Ok`- Return a random nonce value that is used in this transaction
/// * `Err` - Error from TCP connection
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If there was an error when writing to a TCP stream
///
pub fn send_pubkey(stream: &TcpStream, pk: &PkP384, verbose: bool) -> Result<Vec<u8>> {
    let nonce: Vec<u8> = rand::thread_rng().gen::<[u8; 9]>().to_vec();
    if verbose {
        println!("Nonce {:02X?} Len: {}", nonce, nonce.len());
    }
    match send_request(&stream, nonce.as_slice(), &pk) {
        Ok(v) => {
            if verbose {
                println!("{} bytes written", v);
            }
        }
        Err(e) => return Err(e),
    };
    Ok(nonce)
}

/// Send a WebAssembly program to a service
///
/// Send WASM code to a remote service via secure channel.
///
/// # Arguments
///
/// * `stream` - TCP connection stream to a server
/// * `cipher` - Handle for the AES128 encryption
/// * `wasm`- WASM code to be loaded
/// * `verbose` - Verbose mode setting
/// * `skip` - Do not send WASM program
///
/// # Returns
///
/// This function returns the 'Result'
///
/// * `Ok`- WASM code sending was successful
/// * `Err` - Error in WASM code sending
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If WASM code encryption failed
/// * If encrypted WASM sending failed
/// * If ack error was received from the enclave
///
pub fn send_wasm(
    stream: &TcpStream,
    cipher: &Aes128,
    wasm: &mut Vec<u8>,
    verbose: bool,
    skip: bool,
) -> Result<()> {
    if skip {
        return Ok(());
    }
    let encrypted: Vec<u8> = match encrypt(wasm, &cipher) {
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

    // Read reply status for the code loading
    let mut _received: Vec<u8> = match schannel_read(&stream) {
        Ok(v) => v,
        Err(_) => panic!("Read error"),
    };
    if verbose {
        println!("WASM program sent");
    }
    Ok(())
}

/// Send a service request
///
/// The request includes a nonce value and a public key of the client.
/// The size of the nonce is passed in the first byte.
///
/// # Arguments
///
/// * `stream` - TCP connection stream to a server
/// * `nonce` - Random nonce
/// * `pk`- Client public key
///
/// # Returns
///
/// This function returns the output of the command execution as a `Result`:
///
/// * `Ok`- Contains number of bytes written
/// * `Err` - Error from TCP connection
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If there was an error when writing to a TCP stream
/// * If there was an error in TCP flush operation
///
fn send_request(mut stream: &TcpStream, nonce: &[u8], pk: &PkP384) -> Result<usize> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.push(nonce.len() as u8);
    buffer.extend(nonce);
    let bytes = pk.to_bytes();
    buffer.extend(bytes);
    let bytes_written = stream.write(&buffer)?;
    stream.flush()?;
    Ok(bytes_written)
}
