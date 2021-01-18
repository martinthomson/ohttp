//
// License CC0: https://creativecommons.org/publicdomain/zero/1.0/
//

#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // Too lazy to document.

use std::convert::TryFrom;
use std::io;
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
const COOKIE: &[u8] = b"cookie";
const HOST: &[u8] = b"host";
const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
const CHUNKED: &[u8] = b"chunked";

pub type StatusCode = u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "write-bhttp")]
pub enum Mode {
    Known,
    Indefinite,
}

#[derive(Debug)]
pub enum Error {
    /// A field contained invalid Unicode.
    CharacterEncoding(std::string::FromUtf8Error),
    /// A field contained an integer value that was out of range.
    IntRange(std::num::TryFromIntError),
    /// An IO error.
    Io(io::Error),
    /// A field or line was missing a necessary character.
    Missing(u8),
    /// A URL was missing a key component.
    MissingUrlComponent,
    /// An obs-fold line was the first line of a field section.
    ObsFold,
    /// A field contained a non-integer value.
    ParseInt(std::num::ParseIntError),
    /// A URL could not be parsed into components.
    UrlParse(url::ParseError),
}

macro_rules! forward_errors {
    {$($t:path => $v:ident),* $(,)?} => {
        $(
            impl From<$t> for Error {
                fn from(e: $t) -> Self {
                    Self::$v(e)
                }
            }
        )*

        impl std::error::Error for Error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $( Self::$v(e) => Some(e), )*
                    _ => None,
                }
            }
        }
    };
}

forward_errors! {
    io::Error => Io,
    std::string::FromUtf8Error => CharacterEncoding,
    std::num::ParseIntError => ParseInt,
    std::num::TryFromIntError => IntRange,
    url::ParseError => UrlParse,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

type Res<T> = Result<T, Error>;

#[cfg(feature = "write-bhttp")]
#[allow(clippy::cast_possible_truncation)]
fn write_uint(v: impl Into<u64>, n: u8, w: &mut impl io::Write) -> Res<()> {
    let v = v.into();
    assert!(n > 0 && usize::from(n) < std::mem::size_of::<u64>());
    for i in 0..n {
        w.write_all(&[((v >> (8 * (n - i - 1))) & 0xff) as u8])?;
    }
    Ok(())
}

#[cfg(feature = "write-bhttp")]
fn write_varint(v: impl Into<u64>, w: &mut impl io::Write) -> Res<()> {
    let v = v.into();
    match () {
        _ if v < (1 << 6) => write_uint(v, 1, w),
        _ if v < (1 << 14) => write_uint(v | (1 << 14), 2, w),
        _ if v < (1 << 30) => write_uint(v | (2 << 30), 4, w),
        _ if v < (1 << 62) => write_uint(v | (3 << 62), 8, w),
        _ => panic!("Varint value too large"),
    }
}

#[cfg(feature = "write-bhttp")]
fn write_len(len: usize, w: &mut impl io::Write) -> Res<()> {
    write_varint(u64::try_from(len).unwrap(), w)
}

#[cfg(feature = "write-bhttp")]
fn write_vec(v: &[u8], w: &mut impl io::Write) -> Res<()> {
    write_varint(u64::try_from(v.len()).unwrap(), w)?;
    w.write_all(v)?;
    Ok(())
}

#[cfg(feature = "read-bhttp")]
fn read_varint(r: &mut impl io::BufRead) -> Res<u64> {
    fn read_uint(n: usize, r: &mut impl io::BufRead) -> Res<u64> {
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

#[cfg(feature = "read-bhttp")]
fn read_vec(r: &mut impl io::BufRead) -> Res<Vec<u8>> {
    let len = read_varint(r)?;
    let mut v = vec![0; usize::try_from(len).unwrap()];
    r.read_exact(&mut v)?;
    Ok(v)
}

#[cfg(feature = "read-http")]
fn is_ows(x: u8) -> bool {
    x == SP || x == HTAB
}

#[cfg(feature = "read-http")]
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

#[cfg(feature = "read-http")]
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

#[cfg(feature = "read-http")]
fn split_at(v: u8, mut line: Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
    index_of(v, &line).map(|i| {
        let tail = line.split_off(i + 1);
        let _ = line.pop();
        (line, tail)
    })
}

#[cfg(feature = "read-http")]
fn read_line(r: &mut impl io::BufRead) -> Res<Vec<u8>> {
    let mut buf = Vec::new();
    r.read_until(NL, &mut buf)?;
    assert_eq!(buf.pop().unwrap(), NL); // TODO (deal with EOF)
    if buf.pop().ok_or(Error::Missing(CR))? == CR {
        Ok(buf)
    } else {
        Err(Error::Missing(CR))
    }
}

pub struct Field {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Field {
    #[must_use]
    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Self {
        Self { name, value }
    }

    #[cfg(feature = "write-http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
        w.write_all(&self.name)?;
        w.write_all(b": ")?;
        w.write_all(&self.value)?;
        w.write_all(b"\r\n")?;
        Ok(())
    }

    #[cfg(feature = "write-bhttp")]
    pub fn write_bhttp(&self, w: &mut impl io::Write) -> Res<()> {
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
pub struct FieldSection(Vec<Field>);
impl FieldSection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gets the value from the first instance of the field.
    #[must_use]
    pub fn get(&self, n: &[u8]) -> Option<&[u8]> {
        for f in &self.0 {
            if &f.name[..] == n {
                return Some(&f.value);
            }
        }
        None
    }

    #[must_use]
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

    #[cfg(feature = "read-http")]
    fn parse_line(fields: &mut Vec<Field>, line: Vec<u8>) -> Res<()> {
        // obs-fold is helpful in specs, so support it here too
        let f = if is_ows(line[0]) {
            let mut e = fields.pop().ok_or(Error::ObsFold)?;
            e.obs_fold(&line);
            e
        } else if let Some((n, v)) = split_at(COLON, line) {
            let mut name = Vec::from(trim_ows(&n));
            downcase(&mut name);
            let value = Vec::from(trim_ows(&v));
            Field::new(name, value)
        } else {
            return Err(Error::Missing(COLON));
        };
        fields.push(f);
        Ok(())
    }

    #[cfg(feature = "read-http")]
    pub fn read_http(r: &mut impl io::BufRead) -> Res<Self> {
        let mut fields = Vec::new();
        loop {
            let line = read_line(r)?;
            if trim_ows(&line).is_empty() {
                return Ok(Self(fields));
            }
            Self::parse_line(&mut fields, line)?;
        }
    }

    #[cfg(feature = "read-bhttp")]
    pub fn read_bhttp(mode: Mode, r: &mut impl io::BufRead) -> Res<Self> {
        if mode == Mode::Known {
            let buf = read_vec(r)?;
            return Self::read_bhttp(Mode::Indefinite, &mut io::BufReader::new(&buf[..]));
        }
        let mut fields = Vec::new();
        let mut cookie_index: Option<usize> = None;
        loop {
            let n = read_vec(r)?; // TODO deal with empty read here.
            if n.is_empty() {
                return Ok(Self(fields));
            }
            let mut v = read_vec(r)?;
            if n == COOKIE {
                if let Some(i) = &cookie_index {
                    fields[*i].value.extend_from_slice(b"; ");
                    fields[*i].value.append(&mut v);
                    continue;
                }
                cookie_index = Some(fields.len());
            }
            fields.push(Field::new(n, v));
        }
    }

    #[cfg(feature = "write-bhttp")]
    fn write_bhttp_headers(&self, w: &mut impl io::Write) -> Res<()> {
        for f in &self.0 {
            f.write_bhttp(w)?;
        }
        Ok(())
    }

    #[cfg(feature = "write-bhttp")]
    pub fn write_bhttp(&self, mode: Mode, w: &mut impl io::Write) -> Res<()> {
        if mode == Mode::Known {
            let mut buf = Vec::new();
            self.write_bhttp_headers(&mut buf)?;
            write_vec(&buf, w)?;
        } else {
            self.write_bhttp_headers(w)?;
            write_len(0, w)?;
        }
        Ok(())
    }

    #[cfg(feature = "write-http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
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
    #[cfg(feature = "read-http")]
    pub fn read_http(line: Vec<u8>) -> Res<Self> {
        //  request-line = method SP request-target SP HTTP-version
        //  status-line = HTTP-version SP status-code SP [reason-phrase]
        let (a, r) = split_at(SP, line).ok_or(Error::Missing(SP))?;
        let (b, _) = split_at(SP, r).ok_or(Error::Missing(SP))?;
        Ok(if index_of(SLASH, &a).is_some() {
            // Probably a response, so treat it as such.
            let status_str = String::from_utf8(b)?;
            let code = status_str.parse::<u16>()?;
            Self::Response(code)
        } else {
            Self::Request { method: a, url: b }
        })
    }

    #[cfg(feature = "read-bhttp")]
    pub fn read_bhttp(request: bool, r: &mut impl io::BufRead) -> Res<Self> {
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
            Self::Response(u16::try_from(read_varint(r)?)?)
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

    pub fn code(&self, mode: Mode) -> u64 {
        match (self, mode) {
            (Self::Request { .. }, Mode::Known) => 0,
            (Self::Request { .. }, Mode::Indefinite) => 1,
            (Self::Response(_), Mode::Known) => 2,
            (Self::Response(_), Mode::Indefinite) => 3,
        }
    }

    #[cfg(feature = "write-bhttp")]
    pub fn write_bhttp(&self, host: Option<&[u8]>, w: &mut impl io::Write) -> Res<()> {
        match self {
            Self::Request { method, url } => {
                write_vec(method, w)?;

                // Now try to parse the URL.
                let url_str = String::from_utf8(url.clone())?;
                let parsed = if let Ok(parsed) = Url::parse(&url_str) {
                    parsed
                } else if let Some(host) = host {
                    // Try to use the host header to fill in the request.
                    let mut buf = Vec::new();
                    buf.extend_from_slice(b"https://");
                    buf.extend_from_slice(host);
                    buf.extend_from_slice(url);
                    let url_str = String::from_utf8(buf)?;
                    Url::parse(&url_str)?
                } else {
                    return Err(Error::MissingUrlComponent);
                };

                write_vec(parsed.scheme().as_bytes(), w)?;
                let mut authority =
                    String::from(parsed.host_str().ok_or(Error::MissingUrlComponent)?);
                if let Some(port) = parsed.port() {
                    authority.push(':');
                    authority.push_str(&port.to_string());
                }
                write_vec(authority.as_bytes(), w)?;
                let mut path = String::from(parsed.path());
                if let Some(q) = parsed.query() {
                    path.push('?');
                    path.push_str(q);
                }
                write_vec(path.as_bytes(), w)?;
            }
            Self::Response(status) => write_varint(*status, w)?,
        }
        Ok(())
    }

    #[cfg(feature = "write-http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
        match self {
            Self::Request { method, url } => {
                w.write_all(method)?;
                w.write_all(&[SP])?;
                w.write_all(url)?;
                w.write_all(b" HTTP/1.1\r\n")?;
            }
            Self::Response(status) => {
                let buf = format!("HTTP/1.1 {} Reason\r\n", *status);
                w.write_all(buf.as_bytes())?;
            }
        }
        Ok(())
    }
}

pub struct Message {
    informational: Vec<(StatusCode, FieldSection)>,
    control: ControlData,
    header: FieldSection,
    content: Vec<u8>,
    trailer: FieldSection,
}

impl Message {
    #[cfg(feature = "read-http")]
    fn read_chunked(r: &mut impl io::BufRead) -> Res<Vec<u8>> {
        let mut content = Vec::new();
        loop {
            let mut line = read_line(r)?;
            if let Some(i) = index_of(SEMICOLON, &line) {
                let _ = line.split_off(i);
            }
            let count_str = String::from_utf8(line)?;
            let count = usize::from_str_radix(&count_str, 16)?;
            if count == 0 {
                return Ok(content);
            }
            let mut buf = vec![0; count];
            r.read_exact(&mut buf)?;
            assert!(read_line(r)?.is_empty());
            content.append(&mut buf);
        }
    }

    #[cfg(feature = "read-http")]
    pub fn read_http(r: &mut impl io::BufRead) -> Res<Self> {
        let line = read_line(r)?;
        let mut control = ControlData::read_http(line)?;
        let mut informational = Vec::new();
        while let Some(status) = control.informational() {
            let fields = FieldSection::read_http(r)?;
            informational.push((status, fields));
            let line = read_line(r)?;
            control = ControlData::read_http(line)?;
        }

        let header = FieldSection::read_http(r)?;

        let (content, trailer) = if header.is_chunked() {
            let content = Self::read_chunked(r)?;
            let trailer = FieldSection::read_http(r)?;
            (content, trailer)
        } else {
            let mut content = Vec::new();
            if let Some(cl) = header.get(CONTENT_LENGTH) {
                let cl_str = String::from_utf8(Vec::from(cl))?;
                let cl_int = usize::from_str_radix(&cl_str, 10)?;
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

    #[cfg(feature = "write-http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
        for info in &self.informational {
            ControlData::Response(info.0).write_http(w)?;
            info.1.write_http(w)?;
        }
        self.control.write_http(w)?;
        let need_chunked = !self.trailer.is_empty() && !self.header.is_chunked();
        self.header.write_http(w)?;
        if need_chunked {
            write!(w, "Transfer-Encoding: chunked\r\n")?;
        }

        if self.header.is_chunked() {
            write!(w, "{:x}\r\n", self.content.len())?;
            w.write_all(&self.content)?;
            w.write_all(b"\r\n0\r\n")?;
            self.trailer.write_http(w)?;
        }

        Ok(())
    }

    #[cfg(feature = "read-bhttp")]
    pub fn read_bhttp(r: &mut impl io::BufRead) -> Res<Self> {
        let t = read_varint(r)?;
        let request = t == 0 || t == 1;
        let mode = match t {
            0 | 2 => Mode::Known,
            1 | 3 => Mode::Indefinite,
            _ => panic!("Unsupported mode"),
        };

        let mut control = ControlData::read_bhttp(request, r)?;
        let mut informational = Vec::new();
        while let Some(status) = control.informational() {
            let fields = FieldSection::read_bhttp(mode, r)?;
            informational.push((status, fields));
            control = ControlData::read_bhttp(request, r)?;
        }
        let header = FieldSection::read_bhttp(mode, r)?;

        let mut content = read_vec(r)?;
        if mode == Mode::Indefinite && !content.is_empty() {
            loop {
                let mut extra = read_vec(r)?;
                if extra.is_empty() {
                    break;
                }
                content.append(&mut extra);
            }
        }

        let trailer = FieldSection::read_bhttp(mode, r)?;

        Ok(Self {
            informational,
            control,
            header,
            content,
            trailer,
        })
    }

    #[cfg(feature = "write-bhttp")]
    pub fn write_bhttp(&self, mode: Mode, w: &mut impl io::Write) -> Res<()> {
        write_varint(self.control.code(mode), w)?;
        for info in &self.informational {
            write_varint(info.0, w)?;
            info.1.write_bhttp(mode, w)?;
        }
        self.control.write_bhttp(self.header.get(HOST), w)?;
        self.header.write_bhttp(mode, w)?;
        write_vec(&self.content, w)?;
        if mode == Mode::Indefinite {
            write_len(0, w)?;
        }
        self.trailer.write_bhttp(mode, w)?;
        Ok(())
    }
}
