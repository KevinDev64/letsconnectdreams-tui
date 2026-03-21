use std::io::prelude::*;
use std::net::TcpStream;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;
use rand::Rng;

use std::net::{Ipv4Addr, UdpSocket};
use ipnetwork::{IpNetwork, Ipv4Network};

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_SERVER: &str = "stun.nextcloud.com:443";


fn parse_stun_response(buf: &[u8]) -> Result<(IpNetwork, u16), Box<dyn std::error::Error>> {
    let mut i = 20; 
    let mut ip = [0_u8; 4];
    let mut port: u16 = 0;

    while i < buf.len() {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        i += 4;

        // XOR-MAPPED-ADDRESS
        if attr_type == 0x0020 {
            let family = buf[i + 1];
            port = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            if family == 0x01 {
                for j in 0..4 {
                    ip[j] = buf[i + 4 + j] ^ (STUN_MAGIC_COOKIE.to_be_bytes()[j]);
                }
            }
        }

        i += attr_len;
        if attr_len % 4 != 0 {
            i += 4 - (attr_len % 4);
        }
    }

    return Ok((IpNetwork::V4(
                Ipv4Network::new(
                    Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), 
                    0_u8)
                .unwrap()), 
                port))

}

fn get_address_from_stun() -> Result<(IpNetwork, u16), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut buf = [0u8; 20];

    buf[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    let mut rng = rand::thread_rng();
    for i in 8..20 {
        buf[i] = rng.r#gen();
    }

    socket.send_to(&buf, STUN_SERVER)?;
    let mut response = [0u8; 1024];
    let (size, _) = socket.recv_from(&mut response)?;

    parse_stun_response(&response[..size])
}

fn main() {
	let mut stream = TcpStream::connect("127.0.0.1:4222")
			.expect("Failed to connect!");
		
	let user_input = String::from("ECHOOO");
	let user_input = user_input.as_bytes();
	
	let mut message: [u8; 12] = [0; 12];
	for i in 2..8 {
		message[i] = user_input[i-2];
	}
	let length: u32 = 4;
	let length_bytes: [u8; 4] = length.to_be_bytes();
	for i in 8..12 {
		message[i] = length_bytes[i-8];
	}

	println!("Header -> {:?}", &message);
	stream.write_all(&message).expect("Failed to send header!");
	
	let data_buffer = b"data";
	println!("Data -> {:?}", data_buffer);
	stream.write_all(data_buffer).expect("Failed to send data!");

	let mut header_buffer  = [0_u8; 12];
	stream.read(&mut header_buffer).expect("Failed to receive ECHOOO answer!");
	let message_type = str::from_utf8(&header_buffer[2..8]).expect("Wrong message type in answer!");
	let mut raw_length = vec![0_u8; 4];
	raw_length[..].copy_from_slice(&header_buffer[8..12]);
	let received_length = u32::from_be_bytes(raw_length.as_array().unwrap().to_owned());
	if (message_type == "ECHOOO") && (received_length == length) {
		println!("ECHOOO header is correct!")
	} else {
		eprintln!("BAD HEADER SECTION!");
	}

	let mut data_buffer = vec![0_u8; received_length.try_into().unwrap()];
    stream.read(&mut data_buffer).expect("Failed to receive data section!");
    let data = str::from_utf8(&mut data_buffer).to_owned().unwrap();
	if data == "data" {
		println!("Data section is correct!");
	} else {
		eprintln!("BAD DATA SECTION!");
	}

	let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 3072)
        .expect("Failed to generate RSA keypair!");
    let public_key = RsaPublicKey::from(&private_key);
	let public_key_string = public_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();
	let public_key_raw = public_key_string.as_bytes();
	let length = (public_key_raw.len() as u32).to_be_bytes();
	let mut header_buffer = [0_u8; 12];
	header_buffer[2..8].copy_from_slice(b"PUBKEY");
	header_buffer[8..12].copy_from_slice(&length);
	stream.write_all(&header_buffer).unwrap();
	stream.write_all(public_key_raw).unwrap();

	let mut header_buffer = [0_u8; 12];
	header_buffer[2..8].copy_from_slice(b"PUBSRV");
	stream.write_all(&header_buffer).expect("Failed to send PUBSRV command!");

	let mut header_buffer = [0_u8; 12];
	stream.read(&mut header_buffer).expect("Failed to read header after requesting server's pubkey!");
	if !(&header_buffer[2..8] == b"PUBKEY") {
		panic!("Wrong answer from SERVER when trying to get server's pubkey!");
	}
	let mut raw_length = vec![0_u8; 4];
	raw_length[..].copy_from_slice(&header_buffer[8..12]);
	let length = u32::from_be_bytes(raw_length.as_array().unwrap().to_owned());
	let mut data_buffer = vec![0_u8; length.try_into().unwrap()];
	stream.read(&mut data_buffer).expect("Failed to read data section!");
	let server_pub_key = str::from_utf8(&data_buffer).unwrap();
	let server_pub_key = RsaPublicKey::from_pkcs1_pem(server_pub_key).unwrap();
	println!("YES! Server's public key: {:?}", server_pub_key);

	let mut header_buffer = [0_u8; 12];
	header_buffer[2..8].copy_from_slice(b"HELLOO");
	let data = String::from("I'm client!");
	let data = data.as_bytes();
	let mut rng = OsRng;
    let data = server_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .expect("Failed to encrypt message!");
	let length = data.len() as u32;
	let length_raw = length.to_be_bytes();
	header_buffer[8..12].copy_from_slice(&length_raw);

	stream.write_all(&header_buffer).expect("Failed to send HELLOO!");
	stream.write_all(&data).expect("Failed to send HELLOO data!");

	let mut header_buffer = [0_u8; 12];
	stream.read(&mut header_buffer).expect("Failed to read HELLOO answer header!");
	if !(&header_buffer[2..8] == b"HELLOO") {
		panic!("Wrong answer from SERVER when trying to get HELLOO answer!");
	}
	let mut raw_length = vec![0_u8; 4];
	raw_length[..].copy_from_slice(&header_buffer[8..12]);
	let length = u32::from_be_bytes(raw_length.as_array().unwrap().to_owned());
	let mut data_buffer = vec![0_u8; length.try_into().unwrap()];
	stream.read(&mut data_buffer).expect("Failed to read data section!");
	let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &data_buffer)
        .expect("Failed to decrypt message!");	
	let decrypted = str::from_utf8(&decrypted).unwrap();
	if !(decrypted == "I'm server!") {
		panic!("Wrong HELLOO message from server!");
	}
	println!("HELLOO message from SERVER: {}", decrypted);

	let mut header_buffer = [0_u8; 12];
	header_buffer[2..8].copy_from_slice(b"AUTHIN");
	let data = String::from("root root");
	let data_bytes = data.as_bytes();
	let encrypted_data = server_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data_bytes)
        .expect("Failed to encrypt message!");
	let length = (encrypted_data.len() as u32).to_be_bytes();
	header_buffer[8..12].copy_from_slice(&length);
	stream.write_all(&header_buffer).expect("Failed to send AUTHIN header!");
	stream.write_all(&encrypted_data).expect("Failed to send AUTHIN data!");

	let mut header_buffer = [0_u8; 12];
	stream.read(&mut header_buffer).expect("Failed to read AUTHIN answer header!");
	let is_authorized = match str::from_utf8(&header_buffer[2..8]).unwrap() {
		"AUTHOK" => {
			true
		},
		"AUTHER" => {
			false
		},
		_ => { 
			panic!("Wrong answer from SERVER when trying to get result of auth!"); 
		}
	};
	if is_authorized {
		println!("Auth SUCCESS!");
	} else {
		println!("Auth FAILED!");
	}

	let mut header_buffer = [0_u8; 12];
	header_buffer[2..8].copy_from_slice(b"UPDADR");
	let data = String::from("0.0.0.0/0 1234");
	let data_bytes = data.as_bytes();
	let encrypted_data = server_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data_bytes)
        .expect("Failed to encrypt message!");
	let length = (encrypted_data.len() as u32).to_be_bytes();
	header_buffer[8..12].copy_from_slice(&length);
	stream.write_all(&header_buffer).expect("Failed to send UPDADR header!");
	stream.write_all(&encrypted_data).expect("Failed to send UPDADR data!");

	let abort_buffer = b"\0\0ABORTT\0\0\0\0";
	stream.write_all(abort_buffer).expect("Failed to send ABORTT command!");

	stream.shutdown(std::net::Shutdown::Both).expect("Failed to close stream!");

	let mut stream = TcpStream::connect("127.0.0.1:4222")
			.expect("Failed to connect!");
	let mut header_buffer = [0_u8; 12];
	header_buffer[2..8].copy_from_slice(b"UPDADR");
	let data = String::from("1.1.1.1/0 5555");
	let data_bytes = data.as_bytes();
	let encrypted_data = server_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data_bytes)
        .expect("Failed to encrypt message!");
	let length = (encrypted_data.len() as u32).to_be_bytes();
	header_buffer[8..12].copy_from_slice(&length);
	stream.write_all(&header_buffer).expect("Failed to send UPDADR header!");
	stream.write_all(&encrypted_data).expect("Failed to send UPDADR data!");

	let mut header_buffer = [0_u8; 12];
	stream.read(&mut header_buffer).expect("Failed to read UPDADR (must be failed) answer!");
	if &header_buffer[2..8] == b"FORBID" {
		println!("FORBID test -> success!");
	} else {
		panic!("Expected FORBID, but I got {}", str::from_utf8(&header_buffer[2..8]).unwrap())
	}

	let abort_buffer = b"\0\0ABORTT\0\0\0\0";
	stream.write_all(abort_buffer).expect("Failed to send ABORTT command!");

	stream.shutdown(std::net::Shutdown::Both).expect("Failed to close stream!");
	
}
