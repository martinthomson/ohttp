// Rather than grapple with #[cfg(...)] for every variable and import.
#![cfg(all(feature = "http", feature = "bhttp"))]

use bhttp::Message;
use bhttp::Mode;
use std::io::BufReader;

const CHUNKED_HTTP: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: camel, chunked\r\n\r\n4\r\nThis\r\n6\r\n conte\r\n13;chunk-extension=foo\r\nnt contains CRLF.\r\n\r\n0\r\nTrailer: text\r\n\r\n";
const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
const CHUNKED_KNOWN: &[u8] = &[
    0x02, 0x40, 0xc8, 0x00, 0x1d, 0x54, 0x68, 0x69, 0x73, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
    0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x43, 0x52, 0x4c, 0x46, 0x2e,
    0x0d, 0x0a, 0x0d, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x65, 0x72, 0x04, 0x74, 0x65, 0x78, 0x74,
];
const CHUNKED_INDEFINITE: &[u8] = &[
    0x03, 0x40, 0xc8, 0x00, 0x1d, 0x54, 0x68, 0x69, 0x73, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
    0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x43, 0x52, 0x4c, 0x46, 0x2e,
    0x0d, 0x0a, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x65, 0x72, 0x04, 0x74, 0x65, 0x78, 0x74,
    0x00,
];

fn hex(buf: &[u8]) -> String {
    const H: &[char] = &[
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut r = String::with_capacity(buf.len() * 2);
    for v in buf {
        r.push(H[usize::from(*v >> 4)]);
        r.push(H[usize::from(*v & 0xf)]);
    }
    r
}

#[test]
fn chunked_read() {
    let _ = Message::read_http(&mut BufReader::new(CHUNKED_HTTP)).unwrap();
}

#[test]
fn chunked_read_known() {
    let _ = Message::read_bhttp(&mut BufReader::new(CHUNKED_KNOWN)).unwrap();
}

#[test]
fn chunked_read_indefinite() {
    let _ = Message::read_bhttp(&mut BufReader::new(CHUNKED_INDEFINITE)).unwrap();
}

#[test]
fn chunked_to_known() {
    let m = Message::read_http(&mut BufReader::new(CHUNKED_HTTP)).unwrap();
    assert!(m.header().get(TRANSFER_ENCODING).is_none());

    let mut buf = Vec::new();
    m.write_bhttp(Mode::KnownLength, &mut buf).unwrap();
    println!("result: {}", hex(&buf));
    assert_eq!(&buf[..], CHUNKED_KNOWN);
}

#[test]
fn chunked_to_indefinite() {
    let m = Message::read_http(&mut BufReader::new(CHUNKED_HTTP)).unwrap();
    assert!(m.header().get(TRANSFER_ENCODING).is_none());

    let mut buf = Vec::new();
    m.write_bhttp(Mode::IndefiniteLength, &mut buf).unwrap();
    println!("result: {}", hex(&buf));
    assert_eq!(&buf[..], CHUNKED_INDEFINITE);
}
