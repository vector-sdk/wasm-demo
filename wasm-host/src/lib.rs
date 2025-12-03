//! A small library that handles incoming connection requests
//!
//! # Features
//! - Parse host proxy command-line arguments
//! - Process requests and create a thread to handle an incoming connection
//! - Manage connection slots
//!
//! # Dependencies
//! This library relies on the following crates:
//! - `static_dh_ecdh`: For Elliptic Diffie-Hellman key exchange
//! - `io`: For channel reading, writing, and error/status states
//! - `happ`: VECTOR Rust SDK host application library
//!

// SPDX-License-Identifier: MIT
// Copyright (C) 2025 VTT Technical Research Centre of Finland Ltd

extern crate happ;
extern crate lazy_static;
extern crate std;

use clap::Parser;

use lazy_static::lazy_static;
use schannel_lib::*;
use static_dh_ecdh::ecdh::ecdh::FromBytes;
use static_dh_ecdh::ecdh::ecdh::PkP384;
use static_dh_ecdh::ecdh::ecdh::ToBytes;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::str::from_utf8;
use std::sync::Mutex;
use std::thread;

use happ::builder::{Builder, Loadable};
use happ::device::KEYSTONE_DEVICE_PATH;
use happ::ocall::{Listener, OCall};
use happ::{Enclave, Error, Status};

// Ocall identifier
const OCALL_PRINT: u32 = 0x2;

// Ecall identifiers
const ECALL_KEYGEN: u32 = 0x4;
const ECALL_PROCESS: u32 = 0x3;

// Size of the message length field in bytes
const MSG_LENGTH_SIZE: usize = 2;



// Empty listener
struct Printer {}

#[derive(Parser, Debug)]
#[command(author, version)]
#[command(about = "Load Keystone Enclave WebAssembly runtime")]
pub struct Cli {
    /// Enclave application
    #[clap(short, long)]
    eapp: Option<String>,
    /// Enclave runtime
    #[clap(short, long)]
    runtime: Option<String>,
    /// Loader
    #[clap(short, long)]
    loader: Option<String>,
    /// Listening address
    #[clap(short, long, default_value = "0.0.0.0:3333")]
    address: Option<String>,
    /// Verbose mode
    #[clap(short, long, default_value_t = false)]
    pub verbose: bool,
}

/// Parse command-line options
///
/// Using Clap derive-mode to specify command-line parameters.
/// Parameters are specified in 'struct Cli'. Boolean parameter
/// verbose is marked as public so it can be directly referred.
/// Mandatory parameters enclave application, runtime, and loader
/// are checked. Also the lostening address is expected. The
/// default value for the listening port is '3333'.
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
/// * `Ok`- Pathnames for an enclave aapp, runtime, loader, and listening address
/// * `Err` - Some of mandatory parameters are missing
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If mandatory parameter, an enclave application, is missing
/// * If mandatory parameter, an enclave runtime, is missing
/// * If mandatory parameter, loader, is missing
/// * If mandatory parameter, a listening address, is missing
///
pub fn parse(
    cli: &Cli,
    verbose: bool,
) -> Result<(&String, &String, &String, &String), std::io::Error> {
    let app = match &cli.eapp {
        Some(name) => name,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Enclave application is missing",
            ));
        }
    };
    let ert = match &cli.runtime {
        Some(name) => name,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Enclave runtime is missing",
            ));
        }
    };
    let ldr = match &cli.loader {
        Some(name) => name,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Loader is missing",
            ));
        }
    };
    let address = match &cli.address {
        Some(name) => name,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Internal error - address is missing",
            ));
        }
    };
    if verbose {
        println!("Address is {}", address);
    }
    Ok((app, ert, ldr, address))
}

/// Handle new incoming TCP connection in a spawned thread
///
/// Create a secure channel using shared secret derived from emphemeral
/// Elliptic Curve Diffie-Hellman key exchange algorithm and AES
/// encryption. Keep the channel open until a termination message is
/// received. Receive text line messages from the client and return
/// back the word count of the received message.
///
/// # Arguments
///
/// * `stream` - TCP connection stream to a client
/// * `app` - Enclave application
/// * `ert` - Enclave runtime
/// * 'ldr' - Enclave loader
/// * 'id' - Slot index
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
/// * If WASM program file reading failed, e.g., fil eis not found
///
pub fn handle_client(
    stream: TcpStream,
    app: String,
    ert: String,
    ldr: String,
    id: usize,
) -> Result<(), happ::Error> {
    // Receive client's Elliptic Curve public key
    let (nonce, client_pk) = match receive_request(&stream) {
        Ok((nonce, client_pk)) => (nonce, client_pk),
        Err(_) => return Err(Error::Unknown),
    };

    // Build own enclave instance for this thread
    let mut enclave = match build_enclave(&app, &ert, &ldr, id) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Enclave build failed");
            return Err(e);
        }
    };
    let printer = Printer {};
    if let Err(e) = enclave.register_ocall(OCALL_PRINT, &printer) {
        println!("Failed to register ocall print listener");
        return Err(e);
    }
    let handle = match enclave.handle() {
        Ok(handle) => handle,
        Err(e) => {
            println!("Couldn't get handle");
            return Err(e);
        }
    };

    let handler = thread::spawn(move || {
        let mut noncedata: [u8; 9] = [0; 9];
        if nonce.len() >= 9 {
            for i in 0..8 {
                noncedata[i] = nonce[i];
            }
        }
        println!("Attest {}", nonce.len());
        println!("Nonce: {:02X?}", noncedata);
        let mut evidencebytes: Vec<u8> = Vec::new();
        let rv = handle.attest(&noncedata);
        match rv {
            Ok(ref evidence) => {
                evidencebytes.extend(evidence.as_bytes());
                println!("Attestation report: {:02X?}", evidence.as_bytes());
            }
            Err(error) => println!("Error: {}", error as u32),
        }

        // Use ecall to create AES128 key and ECC384 public key
	const AES_KEY_SIZE: usize = 16;
        let mut keydata: [u8; AES_KEY_SIZE] = [0; AES_KEY_SIZE];
        let mut pkdata: Vec<u8> = vec![];

        // Get sealed AES128 key and enclave app Elliptic Curve public key data
        let input = prepare_keygen_ecall_input(&client_pk);
        let output = handle.ecall(ECALL_KEYGEN, Some(input));
        match output {
            Ok((status, data)) => {
                println!("Keygen status: {}", status as u32);
                match data {
                    Some(buffer) => {
                        println!("Keygen response: {:02X?}", buffer);
                        for i in 0..AES_KEY_SIZE {
                            keydata[i] = buffer[i];
                        }
                        pkdata.extend_from_slice(&buffer[AES_KEY_SIZE..buffer.len()]);
                    }
                    None => println!("No data from keygen"),
                }
            }
            Err(error) => println!("Error: {}", error as u32),
        };
        let pk: PkP384 = PkP384::from_bytes(&pkdata).unwrap();

        // Send own Elliptic Curve public key to the client
        match send_reply(&stream, &pk, &evidencebytes) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        // Receive and send messages in the message loop
        loop {
            let received: Vec<u8> = match schannel_read(&stream) {
                Ok(received) => received,
                Err(_) => panic!("Read error"),
            };

            // Call enclave to calculate words from encrypted data
            let mut encrypted: Vec<u8> = vec![];
            let input = prepare_process_ecall_input(&keydata, &received.as_slice());
            let output = handle.ecall(ECALL_PROCESS, Some(input));
            match output {
                Ok((status, data)) => {
                    println!("Process status: {}", status as u32);
                    match data {
                        Some(buffer) => {
                            println!("Process response: {:02X?}", buffer);
                            encrypted.extend_from_slice(&buffer[0..buffer.len()]);
                        }
                        None => println!("No data from process"),
                    }
                }
                Err(error) => {
                    if error == Status::Done {
                        println!("Quit: {}", error as u32);
                        return Ok(());
                    } else {
                        println!("Error: {}", error as u32);
                    }
                }
            };

            // Send reply back to the client
            match schannel_write(&stream, &mut encrypted.as_slice()) {
                Ok(v) => v,
                Err(_) => {
                    println!(
                        "Error occurred, terminating connection with {}",
                        stream.peer_addr().unwrap()
                    );
                    stream.shutdown(Shutdown::Both).unwrap();
                }
            }
        }
    });

    // Run the enclave, this thread will block
    let result = enclave.run();
    match result {
        Ok(retval) => match retval {
            0x0000 => println!("Enclave returned: Success"),
            0xFF01 => println!("Enclave returned: AccessDenied"),
            0xFF02 => println!("Enclave returned: BadArgument"),
            0xFF03 => println!("Enclave returned: BadFormat"),
            0xFF04 => println!("Enclave returned: BadState"),
            0xFF05 => println!("Enclave returned: Device"),
            0xFF06 => println!("Enclave returned: EdgeCall"),
            0xFF07 => println!("Enclave returned: InternalError"),
            0xFF08 => println!("Enclave returned: Interrupted"),
            0xFF09 => println!("Enclave returned: NotFound"),
            0xFF0A => println!("Enclave returned: NotImplemented"),
            0xFF0B => println!("Enclave returned: NotSupported"),
            0xFF0C => println!("Enclave returned: OutOfMemory"),
            0xFF0D => println!("Enclave returned: Pending"),
            0xFF0E => println!("Enclave returned: Panic"),
            0xFF0F => println!("Enclave returned: securityMonitor"),
            0xFF10 => println!("Enclave returned: Unknown"),
            _ => println!("Enclave returned: {}", retval),
        },
        Err(status) => println!("Enclave error: {}", Error::as_usize(status)),
    }

    // Join with the thread
    match handler.join() {
        Ok(_) => println!("Enclave stopped {}", id),
        Err(_) => println!("Enclave has crashed {}", id),
    }
    release_slot_index(id);
    Ok(())
}

/// Find next free slot
pub fn next_slot_index() -> Result<usize, &'static str> {
    let lock = SLOT_MUTEX.lock().unwrap();
    for i in 0..MAX_SLOTS {
        unsafe {
            if CLIENT_SLOTS_USED[(NEXT_FREE_SLOT + i) % MAX_SLOTS] == false {
                CLIENT_SLOTS_USED[(NEXT_FREE_SLOT + i) % MAX_SLOTS] = true;
                let found = (NEXT_FREE_SLOT + i) % MAX_SLOTS;
                NEXT_FREE_SLOT = (NEXT_FREE_SLOT + i + 1) % MAX_SLOTS;
                drop(lock);
                return Ok(found);
            }
        }
    }
    drop(lock);
    println!("All slots are in use - no more clients");
    return Err("All slots are in use");
}

// Shared memory slot handling. Enclave and host has small amount of shared
// memory for communications. Memory is divided to slots allowing at most
// MAX_SLOTS (16) concurrent connections to enclave instances.
lazy_static! {
    static ref SLOT_MUTEX: Mutex<i32> = Mutex::new(0i32);
}
const MAX_SLOTS: usize = 16;
static mut CLIENT_SLOTS_USED: [bool; MAX_SLOTS] = [false; MAX_SLOTS];
static mut NEXT_FREE_SLOT: usize = 0;

/// Release the slot when the client has terminated
fn release_slot_index(id: usize) {
    let lock = SLOT_MUTEX.lock().unwrap();
    if id >= MAX_SLOTS {
        println!("Index out of bounds");
    } else {
        unsafe {
            CLIENT_SLOTS_USED[id] = false;
        }
    }
    drop(lock);
}

/// Get slot base and size information
fn get_slot_info(id: usize) -> Result<(usize, usize), &'static str> {
    if id >= MAX_SLOTS {
        return Err("Index out of bounds");
    }
    let size: usize = Builder::DEFAULT_UNTRUSTED_SIZE / MAX_SLOTS;
    let base: usize = Builder::DEFAULT_UNTRUSTED_PTR + id * size;
    Ok((base, size))
}

impl Listener for Printer {
    // Handle ocalls
    //
    // We have only one ocall that prints debug message from eapps.
    // The messages are assumed to contain UTF-8 strings.
    fn on_ocall(&self, ctx: &mut OCall) -> Status {
        let req = ctx.request();

        println!("Enclave: {:#x} {}", req.as_ptr() as u64, req.len());

        let result = from_utf8(req);
        match result {
            Ok(s) => println!("Enclave: {}", s),
            Err(e) => {
                println!("Enclave error: {}", e);
                println!("Data: {:02X?}", req);
            }
        }

        let bytes: [u8; 4] = 0_u32.to_le_bytes();
        ctx.response()[..bytes.len()].clone_from_slice(&bytes);
        ctx.response_length(bytes.len());
        return Status::Success;
    }
}

/// Prepare input data for keygen ecall
///
/// Two first bytes specify the length of the payload and the payload
/// is the client public key as u8 bytes stored as Box<[u8]> heap
/// allocated array.
fn prepare_keygen_ecall_input(pk: &PkP384) -> Box<[u8]> {
    let bytes = pk.to_bytes();
    let payload_length = bytes.len() as u16;
    let length_bytes = payload_length.to_le_bytes();
    let mut buf: Vec<u8> = Vec::new();
    buf.push(length_bytes[0]);
    buf.push(length_bytes[1]);
    buf.extend(bytes);
    let input: Box<[u8]> = buf.into_boxed_slice();
    input
}

/// Prepare input data for process ecall
///
/// The first two bytes specify the length of the payload. The payload
/// is sealed client AES128 key (16 bytes) and encrypted message bytes.
fn prepare_process_ecall_input(keydata: &[u8; 16], msg: &[u8]) -> Box<[u8]> {
    const AES_KEY_SIZE: usize = 16;
    let payload_length = (msg.len() + AES_KEY_SIZE) as u16;
    let length_bytes = payload_length.to_le_bytes();
    let mut buf: Vec<u8> = Vec::new();
    buf.push(length_bytes[0]);
    buf.push(length_bytes[1]);
    buf.extend(keydata);
    buf.extend(msg);
    let input: Box<[u8]> = buf.into_boxed_slice();
    input
}

/// Receive a service request from the client
///
/// Nonce value and the client public key will be received.
fn receive_request(mut stream: &TcpStream) -> Result<(Vec<u8>, PkP384), happ::Error> {
    const MAX_MESSAGE_SIZE: usize = 2048;
    let mut received: Vec<u8> = vec![];
    let mut nonce: Vec<u8> = vec![];
    let mut rx_bytes = [0u8; MAX_MESSAGE_SIZE];
    loop {
        // Read from the current data in the TcpStream
        let bytes_read = match stream.read(&mut rx_bytes) {
            Ok(bytes_read) => bytes_read,
            Err(_) => return Err(happ::Error::Unknown),
        };
        println!("{} bytes read", bytes_read);
	let nonce_len = (((rx_bytes[1] as u16) << 8) | (rx_bytes[0] as u16)) as usize;
        println!("Nonce length is {}", nonce_len);
        nonce.extend_from_slice(&rx_bytes[MSG_LENGTH_SIZE..nonce_len + MSG_LENGTH_SIZE]);
        // However many bytes we read, extend the `received` string bytes
        received.extend_from_slice(&rx_bytes[nonce_len + MSG_LENGTH_SIZE..bytes_read]);

        // If we didn't fill the array
        // stop reading because there's no more data (we hope!)
        if bytes_read < MAX_MESSAGE_SIZE {
            break;
        }
    }
    let pk: PkP384 = match PkP384::from_bytes(&received) {
        Ok(pk) => pk,
        Err(_) => return Err(happ::Error::Unknown),
    };
    Ok((nonce, pk))
}

/// Send a service reply message
///
/// Own public key and attestation report will be sent.
fn send_reply(mut stream: &TcpStream, pk: &PkP384, evidence: &Vec<u8>) -> Result<(), happ::Error> {
    if evidence.is_empty() {
        println!("Evidence vector is empty");
        return Err(happ::Error::Unknown);
    }
    let mut buffer: Vec<u8> = Vec::new();
    let bytes = pk.to_bytes();
    let payload_length = bytes.len() as u16;
    let length_bytes = payload_length.to_le_bytes();
    buffer.push(length_bytes[0]);
    buffer.push(length_bytes[1]);
    buffer.extend(bytes);
    buffer.extend(evidence);
    let bytes_written = match stream.write(&buffer) {
        Ok(bytes_written) => bytes_written,
        Err(_) => return Err(happ::Error::Unknown),
    };
    println!("{} bytes written", bytes_written);
    if bytes_written < buffer.len() {
        println!("Sent only {}/{} bytes", bytes_written, buffer.len())
    }
    match stream.flush() {
        Ok(_) => (),
        Err(_) => return Err(happ::Error::Unknown),
    }
    Ok(())
}


/// Build an enclave and assign shared memory block
///
/// Each connection will get its own enclave instance. There can be MAX_SLOTS
/// (16) concurrent connections.
fn build_enclave<'a>(
    app: &'a String,
    ert: &'a String,
    ldr: &'a String,
    id: usize,
) -> Result<Enclave<'a>, happ::Error> {
    let mut builder = Builder::new();
    // Setup shared memory bounds
    match get_slot_info(id) {
        Ok((base, size)) => {
            if builder.setup_shared_memory(base, size).is_err() {
                println!("Failed to setup shared memory");
                return Err(Error::Unknown);
            }
        }
        Err(msg) => {
            println!("No slots available {}", msg);
            return Err(Error::Unknown);
        }
    }

    // Setup free memory size
    if builder
        .setup_free_memory(Builder::DEFAULT_FREE_MEMORY_SIZE * 48)
        .is_err()
    {
        println!("Failed to setup free memory");
        return Err(Error::Unknown);
    }

    // Add enclave runtime binary
    if builder.add(&ldr, Loadable::Loader).is_err() {
        println!("Failed to add binary: {}", ldr);
        return Err(Error::Unknown);
    }

    // Add enclave runtime binary
    if builder.add(&ert, Loadable::Runtime).is_err() {
        println!("Failed to add binary: {}", ert);
        return Err(Error::Unknown);
    }

    // Add enclave application binary
    if builder.add(&app, Loadable::Binary).is_err() {
        println!("Failed to add binary: {}", app);
        return Err(Error::Unknown);
    }

    // Create new enclave (opens device)
    let mut enclave = match Enclave::new(KEYSTONE_DEVICE_PATH) {
        Ok(enc) => enc,
        Err(_) => {
            println!("Enclave creation failed");
            return Err(Error::Unknown);
        }
    };

    // Build enclave memory and move it to enclave
    if let Err(_) = enclave.build(&mut builder) {
        println!("Build failed");
        return Err(Error::Unknown);
    }
    Ok(enclave)
}


