//!
//! Keystone enclave application to host tinyWASM runtime
//!
//! The enclave code is packed with Eyrie runtime and binary loader
//! to self-extracting archive with the host application. The host
//! application configures the enclave.
//!

// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

#![no_std]
#![no_main]

extern crate eapp;
extern crate alloc;
extern crate core;

use eapp::eapp_entry;
use eapp::ecall;
use eapp::ocall;
use eapp::attestation;
use eapp::sealing;
use eapp::Status;

use static_dh_ecdh::ecdh::ecdh::{
    ECDHNISTP384, SkP384, PkP384, KeyExchange, FromBytes, ToBytes};
use sha2::{Sha256, Digest};
use generic_array::GenericArray;

use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
};
use alloc::vec::Vec;
use alloc::string::String;
use crate::alloc::string::ToString;
use no_std_compat::str;
use no_std_compat::iter;
use core::arch::asm;
use spin::Mutex;

use tinywasm::{Store, Module, Error, ParseError};

// AES cipher block size
const BLOCK_SIZE: usize = 16;

// Ecall identifiers
const ECALL_KEYGEN: u32 = 0x4;
const ECALL_PROCESS: u32 = 0x3;

// Define global state protected by spin::Mutex and initially empty
// This is a storage for deployed WASM bytecode programs.
static GLOBAL_STATE: Mutex<Option<Vec<u8>>> = Mutex::new(None);

// Ocall identifiers
pub(crate) enum CallID {
    Print = 0x02
}

// Empty listener
struct Handler {
}

// Enclave main program
#[eapp_entry]
pub fn my_eapp_entry() -> u64 {
    // Send first a debug message
    ocall_buf(CallID::Print as u64, "WASM demo enclave".as_bytes());

    // Create a server
    let mut server = ecall::Server::new();

    // Maximum expected input size
    if !server.max_input_size(256) {
        return Status::InternalError as u64;
    }

    // Assure that attestation report can fit to ecall output buffer
    if !server.max_output_size(attestation::REPORT_MAX_LENGTH) {
        return Status::InternalError as u64;
    }

    // Register ecalls
    let handler = Handler{};
    server.register(ECALL_KEYGEN, &handler);
    server.register(ECALL_PROCESS, &handler);

    // Start the service
    let rv = server.serve();

    return rv as u64;
}

impl ecall::Listener for Handler {

    /// Dispatches ecalls to correct handlers
    ///
    /// Switch to functions configured to handle these ecalls. Note that the ids
    /// on the host side should match to these ids. The parameter 'req' contains
    /// input parameter data and output values are returned in a host allocated
    /// buffer assigned to ctx.response.
    ///
    fn on_ecall(&self, ctx: &mut ecall::ECall, req: &[u8]) -> Status {
        match ctx.cid() {
            ECALL_KEYGEN  => {
		ecall_keygen(ctx, req)
	    },
            ECALL_PROCESS => {
		ecall_process(ctx, req)
	    },
            _   => Status::BadCallID,
        }
    }
}

/// Generate a shared secret to be used with a secure channel
///
/// The functions receives an ECC public key of the client and then generates
/// its own ECC keypair. Diffie-Hellman shared secret is generated from the
/// client's public key and own private key. The secret is used to derive an
/// AES key that is also sealed for later use and the sealed data is passed
/// back to the client with own public key. Note that this mechanism is still
/// vulnerable to man-in-the-middle attacks. The use of certified keys is
/// required to prevent that.
///
fn ecall_keygen(ctx: &mut ecall::ECall, req: &[u8]) -> Status {
    ocall_buf(CallID::Print as u64, "KEYGEN".as_bytes());

    // Get client's public key from input data
    let pkdata = parse_keygen_ecall_input(req);
    let client_pk = match PkP384::from_bytes(pkdata) {
        Ok(v) => v,
        Err(_) => return Status::Error,
    };

    // Generate own keypair
    let mut random_bytes: [u8; 32] = [0; 32];
    get_random_seed(&mut random_bytes);
    let (sk, pk) = ecc_keypair_gen(random_bytes);

    // Generate a shared secret
    let ss = ECDHNISTP384::<48>::generate_shared_secret(&sk, &client_pk);

    // Derive AES key from the shared secret
    let mut hasher = Sha256::new();
    hasher.update(&ss.as_ref().unwrap().to_bytes());
    let hash_result = hasher.finalize();
    let mut keydata: Vec<u8> = hash_result[0..16].to_vec();
    let bytes = pk.to_bytes();

    // Seal the AES key to be used in later calls
    let sealed_data_vec = match seal(&mut keydata) {
        Ok(v) => v,
        Err(_) => return Status::Error,
    };

    // Prepare output message as sealed AES128 key and own public key
    let res = ctx.response();
    let len = 16 + bytes.len();
    if len > res.len() {
        return Status::ShortBuffer;
    }
    for i in 0 .. 16 {
        res[i] = sealed_data_vec[i];
    }
    if bytes.len() == len - 16 {
        res[16..len].copy_from_slice(&bytes);
    } else {
        return Status::Error;
    }
    ctx.response_length(len);

    return Status::Success;
}

/// Ecall to calculate words of the input string
///
/// Receive a text string using secure channel, calculate the words of the
/// received string and return the number as a secure channel message.
///
/// Input message format:
/// byte[0]     = Length of the payload (max 256 bytes)
/// byte[1..16] = Sealed AES key to decrypt input data
/// byte[17..]  = Input data (encrypted text string)
///
fn ecall_process(ctx: &mut ecall::ECall, req: &[u8]) -> Status {
    ocall_buf(CallID::Print as u64, "PROCESS".as_bytes());

    if req.is_empty() || req[0] as usize > req.len() - 17 {
        return Status::Error;
    }
    let payload_len = req[0] as usize;
    let mut sealed_keydata: Vec<u8> = req[1..17].to_vec();
    let keydata_vec = match unseal(&mut sealed_keydata) {
        Ok(v) => v,
        Err(_) => return Status::Error,
    };
    let cipher = aes_cipher_gen(&keydata_vec.as_slice());
    if payload_len + 1 > req.len() - 17 {
        return Status::Error;
    }
    let mut received: Vec<u8> = req[17..payload_len + 1].to_vec();
    let mut ivec: Vec<u8> = match decrypt(&mut received, &cipher) {
        Ok(v) => v,
        Err(_) => return Status::Error,
    };
    let decmsg: &[u8] = &ivec;

    if !is_global_state_initialized() {
	init_global_state();
	write_global_state(&mut ivec);
	// Count number of words and encrypt the result
	let count = 1 as usize;
	let reply = count.to_string();
	let mut data = reply.as_bytes().to_vec();
	let encrypted = match encrypt(&mut data, &cipher) {
	    Ok(v) => v,
	    Err(_) => return Status::Error,
	};

	// Prepare encrypted output message
	let res = ctx.response();
	let encrypted_len = encrypted.len();
	if encrypted_len > res.len() {
            return Status::ShortBuffer;
	}
	res[.. encrypted_len].copy_from_slice(&encrypted[..]);
	ctx.response_length(encrypted_len);
	return Status::Success;
    } else {
	let s = match str::from_utf8(decmsg) {
            Ok(v) => v,
            Err(_) => return Status::Error,
	};

	// Message 'q' is used to terminate the client
	if is_quit_command(&s) {
            return Status::Done;
	}

	// Do TinyWASM stuff here. Just testing it.
	let wasm = read_global_state().expect("NO PROGRAM");

	ocall_buf(CallID::Print as u64, "PARSE".as_bytes());
	let module = match Module::parse_bytes(&wasm) {
	    Ok(v) => v,
	    Err(e) => {
		match e {
		    tinywasm::Error::ParseError(ParseError::InvalidType) => return Status::from_u32(0),
		    tinywasm::Error::ParseError(ParseError::UnsupportedSection(_)) => return Status::from_u32(1),
		    tinywasm::Error::ParseError(ParseError::DuplicateSection(_)) => return Status::from_u32(2),
		    tinywasm::Error::ParseError(ParseError::EmptySection(_)) => return Status::from_u32(3),
		    tinywasm::Error::ParseError(ParseError::UnsupportedOperator(_)) => return Status::from_u32(4),
		    tinywasm::Error::ParseError(ParseError::ParseError{ message: _, offset: _ }) => return Status::from_u32(5),
		    tinywasm::Error::ParseError(ParseError::InvalidEncoding(_)) => return Status::from_u32(6),
		    tinywasm::Error::ParseError(ParseError::InvalidLocalCount{ expected: _, actual: _ }) => return Status::from_u32(7),
		    tinywasm::Error::ParseError(ParseError::EndNotReached) => return Status::from_u32(8),
		    tinywasm::Error::ParseError(ParseError::Other(_)) => return Status::from_u32(9),
		    _ => return Status::from_u32(10),
		};
	    },
	};

	// Create a new store
	// Stores are used to allocate objects like functions and globals
	ocall_buf(CallID::Print as u64, "STORE".as_bytes());
	let mut store = Store::default();

	// Instantiate the module
	// This will allocate the module and its globals into the store
	// and execute the module's start function.
	// Every ModuleInstance has its own ID space for functions, globals, etc.
	ocall_buf(CallID::Print as u64, "INSTANTIATE".as_bytes());
	let instance = match module.instantiate(&mut store, None) {
	    Ok(v) => v,
	    Err(_) => return Status::Error,
	};

	//
	// Analyze input message
	ocall_buf(CallID::Print as u64, "PARAMETERS".as_bytes());
	let params = match parse_params(&s) {
	    Some(v) => v,
	    None => return Status::Error,
	};

	// Get a typed handle to the exported "add" function
	// Alternatively, you can use `instance.get_func` to get an untyped handle
	// that takes and returns [`WasmValue`]s
	ocall_buf(CallID::Print as u64, "EXPORT".as_bytes());
	let func = match instance.exported_func::<(i32, i32), i32>(&mut store, params.0) {
	    Ok(v) => v,
	    Err(_) => return Status::Error,
	};
	ocall_buf(CallID::Print as u64, "CALL".as_bytes());
	let res = match func.call(&mut store, (params.1, params.2)) {
	    Ok(v) => v,
	    Err(e) => {
		ocall_buf(CallID::Print as u64, "ERR".as_bytes());
		match e {
		    Error::InvalidLabelType => return Status::Error,
		    Error::InvalidStore => return Status::Error,
		    _ => return Status::Error,
		};
	    },
	};

	// Count number of words and encrypt the result
	let count = res as i32;
	let reply = count.to_string();
	let mut data = reply.as_bytes().to_vec();
	let encrypted = match encrypt(&mut data, &cipher) {
	    Ok(v) => v,
	    Err(_) => return Status::Error,
	};

	// Prepare encrypted output message
	let res = ctx.response();
	let encrypted_len = encrypted.len();
	if encrypted_len > res.len() {
            return Status::ShortBuffer;
	}
	res[.. encrypted_len].copy_from_slice(&encrypted[..]);
	ctx.response_length(encrypted_len);
	return Status::Success;
    }
}

/// Send debug print data to the host as an ocall
///
/// This is a mechanism to send debug messages from the enclave. Messages
/// are printed on the console.
///
pub fn ocall_buf(cid: u64, buffer: &[u8]) -> i32 {
    const OCALL_MAX_BUFFER_SIZE: usize = 32;
    const BUFSIZE: usize = OCALL_MAX_BUFFER_SIZE + ocall::OCall::HEADER_SIZE;
    let mut out: [u8; BUFSIZE] = [0; BUFSIZE];
    let mut ctx = match ocall::OCall::prepare(&mut out) {
        Ok(ctx) => ctx,
        Err(_) => { return -1; }
    };

    let req = ctx.request();
    req[0 .. buffer.len()].copy_from_slice(buffer);

    ctx.request_length(buffer.len());
    if let Err(_) = ctx.call(cid, true) {
        return -1;
    }

    let res = ctx.response();
    let (bytes, _) = res.split_at(core::mem::size_of::<u32>());
    return u32::from_le_bytes(bytes.try_into().unwrap()) as i32;
}

//
// Functions to manage global state (program store)
//

fn init_global_state() {
    let mut state = GLOBAL_STATE.lock();
    *state = Some(Vec::new());
}

fn is_global_state_initialized() -> bool {
    let state = GLOBAL_STATE.lock();
    state.is_some()
}

fn write_global_state(buffer: &mut Vec<u8>) {
    let mut state = GLOBAL_STATE.lock();
    for byte in buffer {
	if let Some(vec) = state.as_mut() {
            vec.push(*byte);
	}
    }
}

fn read_global_state() -> Option<Vec<u8>> {
    let state = GLOBAL_STATE.lock();
    state.clone() // Clones the Vec
}

// Parse input parameters
fn parse_params(input: &str) -> Option<(&str, i32, i32)> {
    let mut parts = input.split_whitespace();
    let function =  parts.next().clone()?;
    let first = parts.next()?.parse::<i32>().ok()?;
    let second = parts.next()?.parse::<i32>().ok()?;
    Some((function, first, second))
}

// Request a 32 byte long random byte sequence
fn get_random_seed(buffer: &mut [u8; 32]) -> Status {
    let mut cycles: u64 = 4;
    // Eapp does not have true randomness source. The performance counter
    // rdtime is used as a source of randomness for demonstrator purpose
    // only. The counter value can be read using RISC-V assembler.
    unsafe {
        asm!("rdtime {cycles}", cycles = inout(reg)cycles);
    }
    let bytes = cycles.to_be_bytes();
    // ocall_buf(CallID::Print as u64, &bytes);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let result = hasher.finalize();
    for i in 0..32 {
        buffer[i] = result[i];
    }
    return Status::Success;
}

// Derive AES128 key from Keystone data sealing key structure
//
// See information about Keystone data sealing data structures from
// https://docs.keystone-enclave.org/
// en/latest/Keystone-Applications/Data-Sealing.html
fn derive_aes128_seal_key() -> Result<[u8; 16], String> {
    let ident = [b'S', b'C', b'H', b'A', b'N', b'N', b'E', b'L'];
    let mut seal_key_struct: [u8; 192] = [0 as u8; 192];
    match sealing::get_sealing_key(&ident, &mut seal_key_struct) {
        Ok(v) => v,
        Err(_) => {
            ocall_buf(CallID::Print as u64, "No seal".as_bytes());
            return Err("Cannot get sealing key".to_string());
        },
    };
    let mut aes128_key: [u8; 16] = [0; 16];
    aes128_key.copy_from_slice(&seal_key_struct[..16]);
    Ok(aes128_key)
}

// Seal data using Keystone sealing key
fn seal(msg: &mut Vec<u8>) -> Result<Vec<u8>, String> {
    let aes128_key = match derive_aes128_seal_key() {
        Ok(v) => v,
        Err(_) => return Err("sealing key derivation failed".to_string()),
    };
    let cipher = aes_cipher_gen(&aes128_key);
    return encrypt(msg, &cipher);
}

// Unseal data using Keystone unsealing key
fn unseal(msg: &mut Vec<u8>) -> Result<Vec<u8>, String> {
    let aes128_key = match derive_aes128_seal_key() {
        Ok(v) => v,
        Err(_) => return Err("unsealing key derivation failed".to_string()),
    };
    let cipher = aes_cipher_gen(&aes128_key);
    return decrypt(msg, &cipher);
}

// The first byte specifies the length of the payload.
fn parse_keygen_ecall_input(data: &[u8]) -> &[u8] {
    let size = data[0] as usize;
    let input = &data[1..size + 1];
    input
}

// Generate an ECC keypair from random seed
fn ecc_keypair_gen(seed: [u8; 32]) -> (SkP384, PkP384) {
    let sk = ECDHNISTP384::<48>::generate_private_key(seed);
    let pk: PkP384 = ECDHNISTP384::<48>::generate_public_key(&sk);
    (sk, pk)
}

// Generate AES128 cipher using the key as a parameter
fn aes_cipher_gen(keydata: &[u8]) -> Aes128 {
    let cipher = Aes128::new(GenericArray::from_slice(&keydata));
    cipher
}

// Add padding to the message
fn pad(buffer: &mut Vec<u8>, block_size: usize) {
    let padding_size = block_size - (buffer.len() % block_size);
    buffer.extend(iter::repeat(padding_size as u8).take(padding_size));
}

// Remove padding from the message
fn un_pad(buffer: &mut Vec<u8>) {
    if let Some(&pad_len) = buffer.last() {
        if pad_len as usize <= BLOCK_SIZE && pad_len as usize <= buffer.len() {
            let len = buffer.len();
            buffer.truncate(len - pad_len as usize);
        }
    }
}

// Encrypt the message using the provided AES128 key
fn encrypt(msg: &mut Vec<u8>, cipher: &Aes128) ->  Result<Vec<u8>, String> {
    pad(msg, BLOCK_SIZE);
    let data: &[u8] = &msg;
    let mut blocks = Vec::new();
    (0..data.len()).step_by(BLOCK_SIZE).for_each(|x| {
        blocks.push(GenericArray::clone_from_slice(&data[x..x + BLOCK_SIZE]));
    });
    cipher.encrypt_blocks(&mut blocks);
    let buffer: Vec<u8> = blocks.into_iter().flatten().collect::<Vec<u8>>();
    Ok(buffer)
}

// Decrypt the message using the provided AES128 key
fn decrypt(msg: &mut Vec<u8>, cipher: &Aes128) ->  Result<Vec<u8>, String> {
    let data: &[u8] = &msg;
    let mut blocks = Vec::new();
    (0..msg.len()).step_by(BLOCK_SIZE).for_each(|x| {
        blocks.push(GenericArray::clone_from_slice(&data[x..x + BLOCK_SIZE]));
    });
    cipher.decrypt_blocks(&mut blocks);
    let mut buffer: Vec<u8> = blocks.into_iter().flatten().collect::<Vec<u8>>();
    un_pad(&mut buffer);
    Ok(buffer)
}

// String "q" from user input is treated as a 'quit' command
fn is_quit_command(msg: &str) -> bool {
    if msg.len() == 1 && msg.eq("q") {
        return true;
    }
    return false;
}
