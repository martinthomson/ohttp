//
// License CC0: https://creativecommons.org/publicdomain/zero/1.0/
//

#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // Too lazy to document.

use std::convert::TryFrom;
use std::io;
use url::Url;

mod err;
mod parse;
mod rw;

pub use err::Error;
use err::Res;
use parse::{
    downcase, index_of, is_ows, read_line, split_at, trim_ows, COLON, COMMA, SEMICOLON, SLASH, SP,
};
use rw::{read_varint, read_vec, write_len, write_varint, write_vec};

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

pub struct Field {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Field {
    #[must_use]
    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Self {
        Self { name, value }
    }

    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
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
    pub fn fields(&self) -> &[Field] {
        &self.0
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

pub enum ControlData {
    Request { method: Vec<u8>, url: Vec<u8> },
    Response(StatusCode),
}

impl ControlData {
    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request{ .. })
    }

    #[must_use]
    pub fn method(&self) -> Option<&[u8]> {
        if let Self::Request { method, .. } = self {
            Some(method)
        } else {
            None
        }
    }

    #[must_use]
    pub fn url(&self) -> Option<&[u8]> {
        if let Self::Request { url, .. } = self {
            Some(url)
        } else {
            None
        }
    }

    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        if let Self::Response(code) = self {
            Some(*code)
        } else {
            None
        }
    }

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
    #[must_use]
    fn informational(&self) -> Option<StatusCode> {
        match self {
            Self::Response(v) if *v >= 100 && *v < 200 => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    fn code(&self, mode: Mode) -> u64 {
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

pub struct InformationalResponse {
    status: StatusCode,
    fields: FieldSection,
}

impl InformationalResponse {
    #[must_use]
    pub fn new(status: StatusCode, fields: FieldSection) -> Self {
        Self { status, fields }
    }

    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn fields(&self) -> &FieldSection {
        &self.fields
    }

    fn write_bhttp(&self, mode: Mode, w: &mut impl io::Write) -> Res<()> {
        write_varint(self.status, w)?;
        self.fields.write_bhttp(mode, w)?;
        Ok(())
    }
}

pub struct Message {
    informational: Vec<InformationalResponse>,
    control: ControlData,
    header: FieldSection,
    content: Vec<u8>,
    trailer: FieldSection,
}

impl Message {
    #[must_use]
    pub fn informational(&self) -> &[InformationalResponse] {
        &self.informational
    }

    #[must_use]
    pub fn control(&self) -> &ControlData {
        &self.control
    }

    #[must_use]
    pub fn header(&self) -> &FieldSection {
        &self.header
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    #[must_use]
    pub fn trailer(&self) -> &FieldSection {
        &self.trailer
    }

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
            informational.push(InformationalResponse::new(status, fields));
            let line = read_line(r)?;
            control = ControlData::read_http(line)?;
        }

        let header = FieldSection::read_http(r)?;

        let (content, trailer) = if matches!(control.status(), Some(204) | Some(304)) {
            // 204 and 304 have no body, no matter what Content-Length says.
            // Unfortunately, we can't do the same for responses to HEAD.
            (Vec::new(), FieldSection::default())
        } else if header.is_chunked() {
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
            ControlData::Response(info.status()).write_http(w)?;
            info.fields().write_http(w)?;
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
            informational.push(InformationalResponse::new(status, fields));
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
            info.write_bhttp(mode, w)?;
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
