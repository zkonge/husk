use std::{io::{Read, Write}, net::TcpStream};

fn main() {
    let stream = TcpStream::connect("www.cloudflare.com:443").unwrap();
    let mut client = baozi::TlsClient::from_tcp(stream).unwrap();
    let _len = client
        .write(b"HEAD / HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")
        .unwrap();

    let mut msg = vec![0u8; 4096];
    client.read(&mut msg).unwrap();
    let msg = String::from_utf8_lossy(&msg);
    println!("msg: \n{}", msg);

    client.close().unwrap();
}
