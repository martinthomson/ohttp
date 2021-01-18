//
// License CC0: https://creativecommons.org/publicdomain/zero/1.0/
//

#![deny(clippy::pedantic)]

use std::convert::TryFrom;
use std::io;
use structopt::StructOpt;
use url::Url;

const HTAB: u8 = 0x09;
const NL: u8 = 0x0a;
const CR: u8 = 0x0d;
const SP: u8 = 0x20;
const COMMA: u8 = 0x2c;
const SLASH: u8 = 0x2f;
const COLON: u8 = 0x3a;
const SEMICOLON: u8 = 0x3b;

const CONTENT_LENGTH: &[u8] = b"content-length";
const HOST: &[u8] = b"host";
const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
const CHUNKED: &[u8] = b"chunked";

type StatusCode = u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BhttpMode {
    Known,
    Indefinite,
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "bhttp",
    about = "Translator between message/http and message/bhttp."
)]
struct Args {
    #[structopt(long, short = "d")]
    decode: bool,
    #[structopt(long, short = "i")]
    indefinite: bool,
}

impl Args {
    fn mode(&self) -> BhttpMode {
        if self.indefinite {
            BhttpMode::Indefinite
        } else {
            BhttpMode::Known
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
fn write_uint(v: impl Into<u64>, n: u8, w: &mut impl io::Write) -> io::Result<()> {
    let v = v.into();
    assert!(n > 0 && usize::from(n) < std::mem::size_of::<u64>());
    for i in 0..n {
        w.write_all(&[((v >> (8 * (n - i - 1))) & 0xff) as u8])?;
    }
    Ok(())
}

fn write_varint(v: impl Into<u64>, w: &mut impl io::Write) -> io::Result<()> {
    let v = v.into();
    match () {
        _ if v < (1 << 6) => write_uint(v, 1, w),
        _ if v < (1 << 14) => write_uint(v | (1 << 14), 2, w),
        _ if v < (1 << 30) => write_uint(v | (2 << 30), 4, w),
        _ if v < (1 << 62) => write_uint(v | (3 << 62), 8, w),
        _ => panic!("Varint value too large"),
    }
}

fn write_len(len: usize, w: &mut impl io::Write) -> io::Result<()> {
    write_varint(u64::try_from(len).unwrap(), w)
}

fn write_vec(v: &[u8], w: &mut impl io::Write) -> io::Result<()> {
    write_varint(u64::try_from(v.len()).unwrap(), w)?;
    w.write_all(v)?;
    Ok(())
}

fn read_varint(r: &mut impl io::BufRead) -> io::Result<u64> {
    fn read_uint(n: usize, r: &mut impl io::BufRead) -> io::Result<u64> {
        let mut buf = [0; 7];
        let count = r.read(&mut buf[..n])?;
        assert_eq!(count, n, "truncated varint");
        let mut v = 0;
        for i in &buf[..n] {
            v = (v << 8) | u64::from(*i);
        }
        Ok(v)
    }

    let b1 = read_uint(1, r)?;
    Ok(match b1 >> 6 {
        0 => b1 & 0x3f,
        1 => ((b1 & 0x3f) << 8) | read_uint(1, r)?,
        2 => ((b1 & 0x3f) << 24) | read_uint(3, r)?,
        3 => ((b1 & 0x3f) << 56) | read_uint(7, r)?,
        _ => unreachable!(),
    })
}

fn read_vec(r: &mut impl io::BufRead) -> io::Result<Vec<u8>> {
    let len = read_varint(r)?;
    let mut v = vec![0; usize::try_from(len).unwrap()];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn is_ows(x: u8) -> bool {
    x == SP || x == HTAB
}

fn trim_ows(v: &[u8]) -> &[u8] {
    for s in 0..v.len() {
        if !is_ows(v[s]) {
            for e in (s..v.len()).rev() {
                if !is_ows(v[e]) {
                    return &v[s..=e];
                }
            }
        }
    }
    &v[..0]
}

fn downcase(n: &mut [u8]) {
    for i in n {
        if *i >= 0x41 && *i <= 0x5a {
            *i += 0x20;
        }
    }
}

fn index_of(v: u8, line: &[u8]) -> Option<usize> {
    for (i, x) in line.iter().enumerate() {
        if *x == v {
            return Some(i);
        }
    }
    None
}

fn split_at(v: u8, mut line: Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
    index_of(v, &line).map(|i| {
        let tail = line.split_off(i + 1);
        let _ = line.pop();
        (line, tail)
    })
}

fn read_line(r: &mut impl io::BufRead) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.read_until(NL, &mut buf)?;
    assert_eq!(
        buf.pop().expect("no content on line"),
        NL,
        "character preceding NL is not CR"
    );
    assert_eq!(
        buf.pop().expect("no character preceding NL"),
        CR,
        "character preceding NL is not CR"
    );
    Ok(buf)
}

struct Field {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Field {
    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Self {
        Self { name, value }
    }

    pub fn write_http(&self, w: &mut impl io::Write) -> io::Result<()> {
        w.write_all(&self.name)?;
        w.write_all(b": ")?;
        w.write_all(&self.value)?;
        w.write_all(b"\r\n")?;
        Ok(())
    }

    pub fn write_bhttp(&self, w: &mut impl io::Write) -> io::Result<()> {
        write_vec(&self.name, w)?;
        write_vec(&self.value, w)?;
        Ok(())
    }

    pub fn obs_fold(&mut self, extra: &[u8]) {
        self.value.push(SP);
        self.value.extend(trim_ows(extra));
    }
}

#[derive(Default)]
struct FieldSection(Vec<Field>);
impl FieldSection {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gets the value from the first instance of the field.
    pub fn get(&self, n: &[u8]) -> Option<&[u8]> {
        for f in &self.0 {
            if &f.name[..] == n {
                return Some(&f.value);
            }
        }
        None
    }

    pub fn is_chunked(&self) -> bool {
        // Look at the last symbol in Transfer-Encoding.
        // This is very primitive decoding; structured field this is not.
        if let Some(te) = self.get(TRANSFER_ENCODING) {
            let mut slc = te;
            while let Some(i) = index_of(COMMA, slc) {
                slc = trim_ows(&slc[i + 1..]);
            }
            slc == CHUNKED
        } else {
            false
        }
    }

    fn parse_line(&mut self, line: Vec<u8>) {
        // obs-fold is helpful in specs, so support it here too
        let f = if is_ows(line[0]) {
            let mut e = self.0.pop().unwrap();
            e.obs_fold(&line);
            e
        } else if let Some((n, v)) = split_at(COLON, line) {
            let mut name = Vec::from(trim_ows(&n));
            downcase(&mut name);
            let value = Vec::from(trim_ows(&v));
            Field::new(name, value)
        } else {
            panic!("field line missing a colon");
        };
        self.0.push(f);
    }

    pub fn read_http(&mut self, r: &mut impl io::BufRead) -> io::Result<()> {
        loop {
            let line = read_line(r).expect("bad field line");
            if trim_ows(&line).is_empty() {
                return Ok(());
            }
            self.parse_line(line);
        }
    }

    pub fn read_bhttp(&mut self, mode: BhttpMode, r: &mut impl io::BufRead) -> io::Result<()> {
        if mode == BhttpMode::Known {
            let buf = read_vec(r)?;
            return self.read_bhttp(BhttpMode::Indefinite, &mut io::BufReader::new(&buf[..]));
        }
        loop {
            let n = read_vec(r)?; // TODO deal with empty read here.
            if n.is_empty() {
                return Ok(());
            }
            let v = read_vec(r)?;
            self.0.push(Field::new(n, v));
        }
    }

    fn write_headers(&self, w: &mut impl io::Write) -> io::Result<()> {
        for f in &self.0 {
            f.write_bhttp(w)?;
        }
        Ok(())
    }

    pub fn write_bhttp(&self, mode: BhttpMode, w: &mut impl io::Write) -> io::Result<()> {
        if mode == BhttpMode::Known {
            let mut buf = Vec::new();
            self.write_headers(&mut buf)?;
            write_vec(&buf, w)?;
        } else {
            self.write_headers(w)?;
            write_len(0, w)?;
        }
        Ok(())
    }

    pub fn write_http(&self, w: &mut impl io::Write) -> io::Result<()> {
        for f in &self.0 {
            f.write_http(w)?;
        }
        w.write_all(b"\r\n")?;
        Ok(())
    }
}

enum ControlData {
    Request { method: Vec<u8>, url: Vec<u8> },
    Response(StatusCode),
}

impl ControlData {
    pub fn read_http(line: Vec<u8>) -> Self {
        //  request-line = method SP request-target SP HTTP-version
        //  status-line = HTTP-version SP status-code SP [reason-phrase]
        let (a, r) = split_at(SP, line).expect("missing SP on request-line or status-line");
        let (b, _) = split_at(SP, r).expect("missing second SP on request-line or status-line");
        if index_of(SLASH, &a).is_some() {
            // Probably a response, so treat it as such.
            let status_str = String::from_utf8(b).expect("non-unicode status code");
            let code = status_str
                .parse::<u16>()
                .expect("bad status code on status-line");
            Self::Response(code)
        } else {
            Self::Request { method: a, url: b }
        }
    }

    pub fn read_bhttp(request: bool, r: &mut impl io::BufRead) -> io::Result<Self> {
        let v = if request {
            let method = read_vec(r)?;
            let mut url = Vec::new();
            let mut scheme = read_vec(r)?;
            url.append(&mut scheme);
            url.extend_from_slice(b"://");
            let mut authority = read_vec(r)?;
            url.append(&mut authority);
            let mut path = read_vec(r)?;
            url.append(&mut path);

            Self::Request { method, url }
        } else {
            Self::Response(u16::try_from(read_varint(r)?).expect("too large status code"))
        };
        Ok(v)
    }

    /// If this is an informational response.
    pub fn informational(&self) -> Option<StatusCode> {
        match self {
            Self::Response(v) if *v >= 100 && *v < 200 => Some(*v),
            _ => None,
        }
    }

    pub fn code(&self, mode: BhttpMode) -> u64 {
        match (self, mode) {
            (Self::Request { .. }, BhttpMode::Known) => 0,
            (Self::Request { .. }, BhttpMode::Indefinite) => 1,
            (Self::Response(_), BhttpMode::Known) => 2,
            (Self::Response(_), BhttpMode::Indefinite) => 3,
        }
    }

    pub fn write_bhttp(&self, host: Option<&[u8]>, w: &mut impl io::Write) -> io::Result<()> {
        match self {
            Self::Request { method, url } => {
                write_vec(method, w)?;

                // Now try to parse the URL.
                let url_str = String::from_utf8(url.clone()).expect("URL is non-unicode");
                let parsed = if let Ok(parsed) = Url::parse(&url_str) {
                    parsed
                } else if let Some(host) = host {
                    // Try to use the host header to fill in the request.
                    let mut buf = Vec::new();
                    buf.extend_from_slice(b"https://");
                    buf.extend_from_slice(host);
                    buf.extend_from_slice(url);
                    let url_str = String::from_utf8(buf).expect("unable to construct URL string");
                    Url::parse(&url_str).expect("unable to parse constructed URL")
                } else {
                    panic!("unable to parse URL and no backup")
                };

                write_vec(parsed.scheme().as_bytes(), w)?;
                let mut authority = String::from(parsed.host_str().unwrap_or(""));
                if let Some(port) = parsed.port() {
                    authority.push(':');
                    authority.push_str(&port.to_string());
                }
                write_vec(authority.as_bytes(), w)?;
                write_vec(parsed.path().as_bytes(), w)?;
            }
            Self::Response(status) => write_varint(*status, w)?,
        }
        Ok(())
    }

    pub fn write_http(&self, w: &mut impl io::Write) -> io::Result<()> {
        match self {
            Self::Request { method, url } => {
                w.write_all(method)?;
                w.write_all(&[SP])?;
                w.write_all(url)?;
                w.write_all(b" HTTP/1.1\r\n")?;
            }
            Self::Response(status) => {
                let buf = format!("HTTP/1.1 {} Reason Phrase\r\n", *status);
                w.write_all(buf.as_bytes())?;
            }
        }
        Ok(())
    }
}

struct Message {
    informational: Vec<(StatusCode, FieldSection)>,
    control: ControlData,
    header: FieldSection,
    content: Vec<u8>,
    trailer: FieldSection,
}

impl Message {
    fn read_chunked(r: &mut impl io::BufRead) -> io::Result<Vec<u8>> {
        let mut content = Vec::new();
        loop {
            let mut line = read_line(r).unwrap();
            if let Some(i) = index_of(SEMICOLON, &line) {
                let _ = line.split_off(i);
            }
            let count_str = String::from_utf8(line).expect("invalid chunked encoding");
            let count = usize::from_str_radix(&count_str, 16).unwrap();
            if count == 0 {
                return Ok(content);
            }
            let mut buf = vec![0; count];
            r.read_exact(&mut buf)?;
            assert!(read_line(r)?.is_empty());
            content.append(&mut buf);
        }
    }

    pub fn read_http(r: &mut impl io::BufRead) -> io::Result<Self> {
        let line = read_line(r).unwrap();
        let mut control = ControlData::read_http(line);
        let mut informational = Vec::new();
        while let Some(status) = control.informational() {
            let mut fields = FieldSection::default();
            fields.read_http(r)?;
            informational.push((status, fields));
            let line = read_line(r).unwrap();
            control = ControlData::read_http(line);
        }

        let mut header = FieldSection::default();
        header.read_http(r)?;

        let (content, trailer) = if header.is_chunked() {
            let content = Self::read_chunked(r)?;
            let mut trailer = FieldSection::default();
            trailer.read_http(r)?;
            (content, trailer)
        } else {
            let mut content = Vec::new();
            if let Some(cl) = header.get(CONTENT_LENGTH) {
                let cl_str = String::from_utf8(Vec::from(cl)).expect("content-length not a string");
                let cl_int =
                    usize::from_str_radix(&cl_str, 10).expect("content-length not an integer");
                content.resize(cl_int, 0);
                r.read_exact(&mut content)?;
            } else {
                // Note that for a request, the spec states that the content is
                // empty, but this just reads all input like for a response.
                r.read_to_end(&mut content)?;
            }
            (content, FieldSection::default())
        };
        Ok(Self {
            informational,
            control,
            header,
            content,
            trailer,
        })
    }

    pub fn write_http(&self, w: &mut impl io::Write) -> io::Result<()> {
        for info in &self.informational {
            ControlData::Response(info.0).write_http(w)?;
            info.1.write_http(w)?;
        }
        self.control.write_http(w)?;
        if !self.trailer.is_empty() && self.header.get(TRANSFER_ENCODING).is_none() {
            write!(w, "Transfer-Encoding: chunked\r\n")?;
        }
        self.header.write_http(w)?;

        if self.header.is_chunked() {
            write!(w, "{:x}\r\n", self.content.len())?;
            w.write_all(&self.content)?;
            w.write_all(b"\r\n0\r\n")?;
        }

        if !self.trailer.is_empty() {
            self.trailer.write_http(w)?;
        }

        Ok(())
    }

    pub fn read_bhttp(r: &mut impl io::BufRead) -> io::Result<Self> {
        let t = read_varint(r)?;
        let request = t == 0 || t == 1;
        let mode = match t {
            0 | 2 => BhttpMode::Known,
            1 | 3 => BhttpMode::Indefinite,
            _ => panic!("Unsupported mode"),
        };

        let mut control = ControlData::read_bhttp(request, r)?;
        let mut informational = Vec::new();
        while let Some(status) = control.informational() {
            let mut fields = FieldSection::default();
            fields.read_bhttp(mode, r)?;
            informational.push((status, fields));
            control = ControlData::read_bhttp(request, r)?;
        }
        let mut header = FieldSection::default();
        header.read_bhttp(mode, r)?;

        let mut content = read_vec(r)?;
        if mode == BhttpMode::Indefinite && !content.is_empty() {
            loop {
                let mut extra = read_vec(r)?;
                if extra.is_empty() {
                    break;
                }
                content.append(&mut extra);
            }
        }

        let mut trailer = FieldSection::default();
        trailer.read_bhttp(mode, r)?;

        Ok(Self {
            informational,
            control,
            header,
            content,
            trailer,
        })
    }

    pub fn write_bhttp(&self, mode: BhttpMode, w: &mut impl io::Write) -> io::Result<()> {
        write_varint(self.control.code(mode), w)?;
        for info in &self.informational {
            write_varint(info.0, w)?;
            info.1.write_bhttp(mode, w)?;
        }
        self.control.write_bhttp(self.header.get(HOST), w)?;
        self.header.write_bhttp(mode, w)?;
        write_vec(&self.content, w)?;
        if mode == BhttpMode::Indefinite {
            write_len(0, w)?;
        }
        self.trailer.write_bhttp(mode, w)?;
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let args = Args::from_args();

    if args.decode {
        let m = Message::read_bhttp(&mut io::BufReader::new(std::io::stdin()))?;
        m.write_http(&mut std::io::stdout())?;
    } else {
        let m = Message::read_http(&mut io::BufReader::new(std::io::stdin()))?;
        m.write_bhttp(args.mode(), &mut std::io::stdout())?;
    }
    Ok(())
}
