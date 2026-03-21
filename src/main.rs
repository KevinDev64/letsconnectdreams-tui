use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{self, TryRecvError};

use letsconnectdreams_tui::*;

fn main() {
    println!("letsconnectdreams CLI {}", CLI_VERSION);
    println!("RSA keypair initialization ...");
    let (priv_key, pub_key) = get_rsa_keypair();

    println!("Loading config.ini ...");
    let config = load_config();

    println!("NetworkClient initialization ...");
    let mut client = NetworkClient {
        public_address: String::from("0.0.0.0"),
        public_port: 0,
        stream: None,
        client_keypair: Keypair { pub_key, priv_key },
        server_pub_key: None
    };

    let (tx, rx) = mpsc::channel();
    let input_thread_handler = thread::spawn(move || {
        input_handler(tx);
    });

    loop {
        match rx.try_recv() {
            Ok(command) => {
                command_handler(command, &config, &mut client);
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