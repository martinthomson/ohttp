// Rather than grapple with #[cfg(...)] for every variable and import.
#![allow(dead_code, unused_imports)]

use bhttp::Message;
#[cfg(feature = "write-bhttp")]
use bhttp::Mode;
use std::io::BufReader;

const CHUNKED_HTTP: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: camel, chunked\r\n\r\n4\r\nThis\r\n6\r\n conte\r\n13;chunk-extension=foo\r\nnt contains CRLF.\r\n\r\n0\r\nTrailer: text\r\n\r\n";
const CHUNKED_KNOWN: &[u8] = &[
    2, 64, 200, 33, 17, 116, 114, 97, 110, 115, 102, 101, 114, 45, 101, 110, 99, 111, 100, 105,
    110, 103, 14, 99, 97, 109, 101, 108, 44, 32, 99, 104, 117, 110, 107, 101, 100, 29, 84, 104,
    105, 115, 32, 99, 111, 110, 116, 101, 110, 116, 32, 99, 111, 110, 116, 97, 105, 110, 115, 32,
    67, 82, 76, 70, 46, 13, 10, 13, 7, 116, 114, 97, 105, 108, 101, 114, 4, 116, 101, 120, 116,
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

#[cfg(feature = "read-http")]
#[test]
fn read_chunked() {
    let _ = Message::read_http(&mut BufReader::new(CHUNKED_HTTP)).unwrap();
}

#[cfg(feature = "read-bhttp")]
fn read_known() {
    let _ = Message::read_bhttp(&mut BufReader::new(CHUNKED_HTTP)).unwrap();
}

#[cfg(all(feature = "read-http", feature = "write-bhttp"))]
#[test]
fn chunked_known() {
    let m = Message::read_http(&mut BufReader::new(CHUNKED_HTTP)).unwrap();
    let mut buf = Vec::new();
    m.write_bhttp(Mode::KnownLength, &mut buf).unwrap();
    println!("result: {}", hex(&buf));
    assert_eq!(&buf[..], CHUNKED_KNOWN);
}
