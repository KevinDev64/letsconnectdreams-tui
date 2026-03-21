use std::net::TcpStream;
use std::sync::mpsc::Sender;
use std::io::{self, Read, Write};
use std::fmt;
use ini::Ini;

use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey,EncodeRsaPrivateKey, Version};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub const CLI_VERSION: &str = "v0.1.0";
pub const PROTOCOL_VERSION: &str = "v0.1.0";

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16
}

#[derive(Debug, Clone)]
pub enum Command {
    Version(),
    Echooo(String),
    Disconnect(),
    Connect()
}

#[derive(Debug)]
pub struct NetworkClient {
    pub public_address: String,
    pub public_port: u16,
    pub stream: Option<TcpStream>
}

impl TryInto<String> for Command {
    type Error = ();
   fn try_into(self) -> Result<String, Self::Error> {
       match self {
            Command::Version() => {
                Ok(format!("version"))
            },
            Command::Echooo(n) => {
                Ok(format!("echooo {}", n))
            },
            Command::Disconnect() => {
                Ok(format!("disconnect"))
            },
            Command::Connect() => {
                Ok(format!("connect"))
            }
        }
   }
}

pub fn input_handler(tx: Sender<Command>) {
    loop {
        // print!("> ");
        // io::stdout().flush().expect("Failed to print basic CLI input form!");
        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input).expect("Failed to read STDIN!");

        let user_input: Vec<&str> = user_input.trim().split_ascii_whitespace().collect();

        match user_input.get(0).unwrap().to_owned() {
            "version" => {
                tx.send(Command::Version()).expect("Failed to send control command from input thread!");
            },
            "echooo" => {
                tx.send(Command::Echooo(user_input.get(1).unwrap().to_string())).expect("Failed to send control command from input thread!");
            },
            "disconnect" => {
                tx.send(Command::Disconnect()).expect("Failed to send control command from input thread!");
            },
            "connect" => {
                tx.send(Command::Connect()).expect("Failed to send control command from input thread!")
            },
            _ => {
                println!("incorrect command.")
            }
        }
    }
}

pub fn check_auth(tx: Sender<Command>, user_input: &str, ) {
    
}

pub fn command_handler(command: Command, config: &Config, client: &mut NetworkClient) {
    match command {
        Command::Version() => {
            println!("\n+++++++++++++++++++++++++++++");
            println!("CLI version: {}", CLI_VERSION);
            println!("PROTOCOL LetsConnectDreams version: {}", PROTOCOL_VERSION);
            println!("Written by KevinDev64 <kevindev56@yandex.ru>");
            println!("+++++++++++++++++++++++++++++\n")
        },
        Command::Echooo(n) => {
            if let None = &client.stream {
                println!("No connection established! Use `connect`.");
                return;
            }
            let stream = client.stream.as_mut().unwrap();
            let mut header_buffer = [0_u8; 12];
            header_buffer[2..8].copy_from_slice(b"ECHOOO");
            let data = n.as_bytes();
            let length = data.len() as u32;
            header_buffer[8..12].copy_from_slice(&length.to_be_bytes());
            stream.write_all(&header_buffer).expect("Failed to send ECHOOO header!");
            stream.write_all(data).expect("Failed to send ECHOOO data!");

            let mut header_buffer = [0_u8; 12];
            stream.read(&mut header_buffer).expect("Failed to read ECHOOO answer header!");
            let mut raw_length = vec![0_u8; 4];
            raw_length[..].copy_from_slice(&header_buffer[8..12]);
            let length = u32::from_be_bytes(raw_length.as_array().unwrap().to_owned());
            let mut data_buffer = vec![0_u8; length.try_into().unwrap()];
	        stream.read(&mut data_buffer).expect("Failed to read data section!");
            let received_data = str::from_utf8(&data_buffer).expect("Failed to parse ECHOOO answer data!");
            if received_data == n.as_str() {
                println!("ECHOOO test -> ok.");
            } else {
                println!("ECHOOO test -> fail.");
            }
        },
        Command::Disconnect() => {
            if let None = &client.stream {
                println!("No connection established! Use `connect`.");
                return;
            }
            let stream = client.stream.as_mut().unwrap();
            let header_buffer = b"\0\0ABORTT\0\0\0\0";
            stream.write_all(header_buffer).expect("Failed to send ABORTT command");
            stream.shutdown(std::net::Shutdown::Both).expect("Failed to shutdown TCP connection!");
            client.stream = None;
            println!("Disconnected from Signaling Server!");
        },
        Command::Connect() => {
            if let Some(_n) = &client.stream {
                println!("You are already connected!");
                return;
            }
            client.stream = match TcpStream::connect(format!("{}:{}", config.host, config.port)) {
                Ok(n) => {
                    println!("Connected!");
                    Some(n)
                },
                Err(e) => {
                    println!("Failed to connect! ({})", e);
                    None
                }                
            };
        }
    }
}

pub fn generate_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 3072)
        .expect("Failed to generate RSA keypair!");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn rsa_encrypt_message(public_key: &RsaPublicKey, message: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, message)
        .expect("Failed to encrypt message!")
}

pub fn rsa_decrypt_message(private_key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    private_key.decrypt(Pkcs1v15Encrypt, message)
        .expect("Failed to decrypt message!")
}

pub fn get_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let priv_key = match RsaPrivateKey::read_pkcs1_pem_file("priv_key.pem") {
        Ok(key) => {
            println!("RSA keypair found!");
            key
        },
        Err(e) => {
            println!("RSA keypair not found! Generating...");
            let (priv_key, _pub_key) = generate_rsa_keypair();
            priv_key.write_pkcs1_pem_file("priv_key.pem", rsa::pkcs8::LineEnding::LF)
                .expect("Failed to write private key file!");
            priv_key
        }
    };
    let pub_key = priv_key.to_public_key();
    (priv_key, pub_key)
}

pub fn load_config() -> Config {
    match Ini::load_from_file("config.ini") {
        Ok(n) => {
            let server_props = n.section(Some("server")).expect("Bad config! Delete it and restart program.");
            let host = server_props.get("host").expect("Bad config! Delete it and restart program.");
            let port = server_props.get("port").expect("Bad config! Delete it and restart program.");
            let port: u16 = port.parse().expect("Bad config! Delete it and restart program.");
            Config { host: host.to_string(), port }
        },
        Err(e) => {
            println!("Failed to load config! Trying to create...");
            let mut conf = Ini::new();
            conf.with_section(Some("server"))
                .set("host", "127.0.0.1")
                .set("port", "4222");
            conf.write_to_file("config.ini").expect("Failed to write generated config!");
            Config { host: "127.0.0.1".to_string(), port: 4222 }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rsa_crypto() {
        use crate::*;
        let (private_key, public_key) = generate_rsa_keypair();
        let some_data = b"some test data";
        let encrypted = rsa_encrypt_message(&public_key, some_data);
        let decrypted = rsa_decrypt_message(&private_key, &encrypted);
        assert_eq!(some_data.to_vec(), decrypted);
    }
}