use std::io::prelude::*;
use std::net::TcpStream;

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

	let abort_buffer = b"\0\0ABORTT\0\0\0\0";
	stream.write_all(abort_buffer).expect("Failed to send ABORTT command!");

	stream.shutdown(std::net::Shutdown::Both).expect("Failed to close stream!");
}
