use bhttp::{Message, Mode};
use ohttp::{init, ClientRequest};
use std::io::{self, BufRead, Write};

fn main() {
    init();
    let mut input = io::BufReader::new(io::stdin());
    print!("Config: ");
    io::stdout().flush().unwrap();
    let mut cfg = String::new();
    input.read_line(&mut cfg).unwrap();
    let config = hex::decode(cfg.trim()).unwrap();
    let client = ClientRequest::new(&config).unwrap();

    println!("Request (HTTP/1.1, terminate with \"END\"):");
    io::stdout().flush().unwrap();
    let mut request_buf = String::new();
    loop {
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        if line.trim() == "END" {
            break;
        }
        request_buf.push_str(line.trim_end());
        request_buf.push_str("\r\n");
    }

    let req = Message::read_http(&mut io::BufReader::new(request_buf.as_bytes())).unwrap();
    let mut request = Vec::new();
    req.write_bhttp(Mode::KnownLength, &mut request).unwrap();
    let (enc_request, client_response) = client.encapsulate(&request).unwrap();

    println!("Encapsulated Request: {}", hex::encode(&enc_request));

    print!("Encapsulated Response: ");
    io::stdout().flush().unwrap();
    let mut rsp = String::new();
    input.read_line(&mut rsp).unwrap();
    let enc_response = hex::decode(rsp.trim()).unwrap();
    let response = client_response.decapsulate(&enc_response).unwrap();

    let res = Message::read_bhttp(&mut io::BufReader::new(&response[..])).unwrap();
    println!("Response:");
    res.write_http(&mut io::stdout()).unwrap();
    println!("END");
    io::stdout().flush().unwrap();
}
