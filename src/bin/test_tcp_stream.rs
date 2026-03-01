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

	let abort_buffer = b"\0\0ABORTT\0\0\0\0";
	stream.write_all(abort_buffer).expect("Failed to send ABORTT command!");

	stream.shutdown(std::net::Shutdown::Both).expect("Failed to close stream!");
}
