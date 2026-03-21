use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{self, TryRecvError};

use letsconnectdreams_tui::*;

fn main() {
    println!("letsconnectdreams CLI v.0.1");
    println!("RSA keypair initialization...");
    let (priv_key, pub_key) = get_rsa_keypair();

    println!("Connecting to Signaling Server...");
    println!("Selected default server!");
    let mut stream = TcpStream::connect("127.0.0.1:4222")
			.expect("Failed to connect. Change your settings!");

    let (tx, rx) = mpsc::channel();
    let input_thread_handler = thread::spawn(move || {
        input_handler(tx);
    });

    loop {
        match rx.try_recv() {
            Ok(command) => {
                command_handler(command, &mut stream);
            },
            Err(TryRecvError::Empty) => {},
            Err(TryRecvError::Disconnected) => {
                println!("Input thread exited!");
                break;
            }
        }
    }
    input_thread_handler.join().expect("Couldn't join on the associated thread!");
}