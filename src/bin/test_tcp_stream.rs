use std::io::prelude::*;
use std::net::TcpStream;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;

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

	let abort_buffer = b"\0\0ABORTT\0\0\0\0";
	stream.write_all(abort_buffer).expect("Failed to send ABORTT command!");

	stream.shutdown(std::net::Shutdown::Both).expect("Failed to close stream!");
}
