use std::{
    io::{Read, Write},
    net::TcpStream,
};

fn main() {
    let stream = TcpStream::connect("cloudflare.com:443").unwrap();
    // let stream = TcpStream::connect("localhost:4443").unwrap();
    let request = b"HEAD / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n";
    println!("{}", String::from_utf8_lossy(request));
    let mut client = husk::TlsClient::from_tcp(stream, "cloudflare.com".to_owned()).unwrap();
    let _len = client.write(request).unwrap();
    let mut msg = vec![0u8; 4096];
    client.read(&mut msg).unwrap();
    let msg = String::from_utf8_lossy(&msg);
    println!("msg: \n{}", msg);

    client.close().unwrap();
}
