#![deny(warnings, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // Too lazy to document these.

use std::{convert::TryFrom, io};

#[cfg(feature = "http")]
use url::Url;

mod err;
mod parse;
mod rw;

use std::borrow::BorrowMut;

pub use err::Error;
use err::Res;
#[cfg(feature = "http")]
use parse::{downcase, is_ows, read_line, split_at, COLON, SEMICOLON, SLASH, SP};
use parse::{index_of, trim_ows, COMMA};
use rw::{read_varint, read_vec, write_len, write_varint, write_vec};

#[cfg(feature = "http")]
const CONTENT_LENGTH: &[u8] = b"content-length";
const COOKIE: &[u8] = b"cookie";
const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
const CHUNKED: &[u8] = b"chunked";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u16);

impl StatusCode {
    pub const OK: Self = StatusCode(200);

    #[must_use]
    pub fn informational(self) -> bool {
        matches!(self.0, 100..=199)
    }

    #[must_use]
    pub fn code(self) -> u16 {
        self.0
    }
}

impl TryFrom<u64> for StatusCode {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::try_from(u16::try_from(value).map_err(|_| Error::InvalidStatus)?)
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if matches!(value, 100..=599) {
            Ok(Self(value))
        } else {
            Err(Error::InvalidStatus)
        }
    }
}

impl From<StatusCode> for u16 {
    fn from(value: StatusCode) -> Self {
        value.code()
    }
}

pub trait ReadSeek: io::BufRead + io::Seek {}
impl<T> ReadSeek for io::Cursor<T> where T: AsRef<[u8]> {}
impl<T> ReadSeek for io::BufReader<T> where T: io::Read + io::Seek {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    KnownLength,
    IndeterminateLength,
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

    #[cfg(feature = "http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
        w.write_all(&self.name)?;
        w.write_all(b": ")?;
        w.write_all(&self.value)?;
        w.write_all(b"\r\n")?;
        Ok(())
    }

    pub fn write_bhttp(&self, w: &mut impl io::Write) -> Res<()> {
        write_vec(&self.name, w)?;
        write_vec(&self.value, w)?;
        Ok(())
    }

    #[cfg(feature = "http")]
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

    pub fn put(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.0.push(Field::new(name.into(), value.into()));
    }

    pub fn iter(&self) -> impl Iterator<Item = &Field> {
        self.0.iter()
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

    /// As required by the HTTP specification, remove the Connection header
    /// field, everything it refers to, and a few extra fields.
    #[cfg(feature = "http")]
    fn strip_connection_headers(&mut self) {
        const CONNECTION: &[u8] = b"connection";
        const PROXY_CONNECTION: &[u8] = b"proxy-connection";
        const SHOULD_REMOVE: &[&[u8]] = &[
            CONNECTION,
            PROXY_CONNECTION,
            b"keep-alive",
            b"te",
            b"trailer",
            b"transfer-encoding",
            b"upgrade",
        ];
        let mut listed = Vec::new();
        let mut track = |n| {
            let mut name = Vec::from(trim_ows(n));
            downcase(&mut name);
            if !listed.contains(&name) {
                listed.push(name);
            }
        };

        for f in self
            .0
            .iter()
            .filter(|f| f.name() == CONNECTION || f.name == PROXY_CONNECTION)
        {
            let mut v = f.value();
            while let Some(i) = index_of(COMMA, v) {
                track(&v[..i]);
                v = &v[i + 1..];
            }
            track(v);
        }

        self.0.retain(|f| {
            !SHOULD_REMOVE.contains(&f.name()) && listed.iter().all(|x| &x[..] != f.name())
        });
    }

    #[cfg(feature = "http")]
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

    #[cfg(feature = "http")]
    pub fn read_http<T, R>(r: &mut T) -> Res<Self>
    where
        T: BorrowMut<R> + ?Sized,
        R: ReadSeek + ?Sized,
    {
        let mut fields = Vec::new();
        loop {
            let line = read_line(r)?;
            if trim_ows(&line).is_empty() {
                return Ok(Self(fields));
            }
            Self::parse_line(&mut fields, line)?;
        }
    }

    fn read_bhttp_fields<T, R>(terminator: bool, r: &mut T) -> Res<Vec<Field>>
    where
        T: BorrowMut<R> + ?Sized,
        R: ReadSeek + ?Sized,
    {
        let r = r.borrow_mut();
        let mut fields = Vec::new();
        let mut cookie_index: Option<usize> = None;
        loop {
            if let Some(n) = read_vec(r)? {
                if n.is_empty() {
                    if terminator {
                        return Ok(fields);
                    }
                    return Err(Error::Truncated);
                }
                let mut v = read_vec(r)?.ok_or(Error::Truncated)?;
                if n == COOKIE {
                    if let Some(i) = &cookie_index {
                        fields[*i].value.extend_from_slice(b"; ");
                        fields[*i].value.append(&mut v);
                        continue;
                    }
                    cookie_index = Some(fields.len());
                }
                fields.push(Field::new(n, v));
            } else if terminator {
                return Err(Error::Truncated);
            } else {
                return Ok(fields);
            }
        }
    }

    pub fn read_bhttp<T, R>(mode: Mode, r: &mut T) -> Res<Self>
    where
        T: BorrowMut<R> + ?Sized,
        R: ReadSeek + ?Sized,
    {
        let fields = if mode == Mode::KnownLength {
            if let Some(buf) = read_vec(r)? {
                Self::read_bhttp_fields(false, &mut io::Cursor::new(&buf[..]))?
            } else {
                Vec::new()
            }
        } else {
            Self::read_bhttp_fields(true, r)?
        };
        Ok(Self(fields))
    }

    fn write_bhttp_headers(&self, w: &mut impl io::Write) -> Res<()> {
        for f in &self.0 {
            f.write_bhttp(w)?;
        }
        Ok(())
    }

    pub fn write_bhttp(&self, mode: Mode, w: &mut impl io::Write) -> Res<()> {
        if mode == Mode::KnownLength {
            let mut buf = Vec::new();
            self.write_bhttp_headers(&mut buf)?;
            write_vec(&buf, w)?;
        } else {
            self.write_bhttp_headers(w)?;
            write_len(0, w)?;
        }
        Ok(())
    }

    #[cfg(feature = "http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
        for f in &self.0 {
            f.write_http(w)?;
        }
        w.write_all(b"\r\n")?;
        Ok(())
    }
}

pub enum ControlData {
    Request {
        method: Vec<u8>,
        scheme: Vec<u8>,
        authority: Vec<u8>,
        path: Vec<u8>,
    },
    Response(StatusCode),
}

impl ControlData {
    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request { .. })
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
    pub fn scheme(&self) -> Option<&[u8]> {
        if let Self::Request { scheme, .. } = self {
            Some(scheme)
        } else {
            None
        }
    }

    #[must_use]
    pub fn authority(&self) -> Option<&[u8]> {
        if let Self::Request { authority, .. } = self {
            if authority.is_empty() {
                None
            } else {
                Some(authority)
            }
        } else {
            None
        }
    }

    #[must_use]
    pub fn path(&self) -> Option<&[u8]> {
        if let Self::Request { path, .. } = self {
            if path.is_empty() {
                None
            } else {
                Some(path)
            }
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

    #[cfg(feature = "http")]
    pub fn read_http(line: Vec<u8>) -> Res<Self> {
        //  request-line = method SP request-target SP HTTP-version
        //  status-line = HTTP-version SP status-code SP [reason-phrase]
        let (a, r) = split_at(SP, line).ok_or(Error::Missing(SP))?;
        let (b, _) = split_at(SP, r).ok_or(Error::Missing(SP))?;
        if index_of(SLASH, &a).is_some() {
            // Probably a response, so treat it as such.
            let status_str = String::from_utf8(b)?;
            let code = StatusCode::try_from(status_str.parse::<u64>()?)?;
            Ok(Self::Response(code))
        } else if index_of(COLON, &b).is_some() {
            // Now try to parse the URL.
            let url_str = String::from_utf8(b)?;
            let parsed = Url::parse(&url_str)?;
            let authority = parsed.host_str().map_or_else(String::new, |host| {
                let mut authority = String::from(host);
                if let Some(port) = parsed.port() {
                    authority.push(':');
                    authority.push_str(&port.to_string());
                }
                authority
            });
            let mut path = String::from(parsed.path());
            if let Some(q) = parsed.query() {
                path.push('?');
                path.push_str(q);
            }
            Ok(Self::Request {
                method: a,
                scheme: Vec::from(parsed.scheme().as_bytes()),
                authority: Vec::from(authority.as_bytes()),
                path: Vec::from(path.as_bytes()),
            })
        } else {
            if a == b"CONNECT" {
                return Err(Error::ConnectUnsupported);
            }
            Ok(Self::Request {
                method: a,
                scheme: Vec::from(&b"https"[..]),
                authority: Vec::new(),
                path: b,
            })
        }
    }

    pub fn read_bhttp<T, R>(request: bool, r: &mut T) -> Res<Self>
    where
        T: BorrowMut<R> + ?Sized,
        R: ReadSeek + ?Sized,
    {
        let v = if request {
            let method = read_vec(r)?.ok_or(Error::Truncated)?;
            let scheme = read_vec(r)?.ok_or(Error::Truncated)?;
            let authority = read_vec(r)?.ok_or(Error::Truncated)?;
            let path = read_vec(r)?.ok_or(Error::Truncated)?;
            Self::Request {
                method,
                scheme,
                authority,
                path,
            }
        } else {
            Self::Response(StatusCode::try_from(
                read_varint(r)?.ok_or(Error::Truncated)?,
            )?)
        };
        Ok(v)
    }

    /// If this is an informational response.
    #[must_use]
    fn informational(&self) -> Option<StatusCode> {
        match self {
            Self::Response(v) if v.informational() => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    fn code(&self, mode: Mode) -> u64 {
        match (self, mode) {
            (Self::Request { .. }, Mode::KnownLength) => 0,
            (Self::Response(_), Mode::KnownLength) => 1,
            (Self::Request { .. }, Mode::IndeterminateLength) => 2,
            (Self::Response(_), Mode::IndeterminateLength) => 3,
        }
    }

    pub fn write_bhttp(&self, w: &mut impl io::Write) -> Res<()> {
        match self {
            Self::Request {
                method,
                scheme,
                authority,
                path,
            } => {
                write_vec(method, w)?;
                write_vec(scheme, w)?;
                write_vec(authority, w)?;
                write_vec(path, w)?;
            }
            Self::Response(status) => write_varint(status.code(), w)?,
        }
        Ok(())
    }

    #[cfg(feature = "http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
        match self {
            Self::Request {
                method,
                scheme,
                authority,
                path,
            } => {
                w.write_all(method)?;
                w.write_all(b" ")?;
                if !authority.is_empty() {
                    w.write_all(scheme)?;
                    w.write_all(b"://")?;
                    w.write_all(authority)?;
                }
                w.write_all(path)?;
                w.write_all(b" HTTP/1.1\r\n")?;
            }
            Self::Response(status) => {
                let buf = format!("HTTP/1.1 {} Reason\r\n", status.code());
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
        write_varint(self.status.code(), w)?;
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
    pub fn request(method: Vec<u8>, scheme: Vec<u8>, authority: Vec<u8>, path: Vec<u8>) -> Self {
        Self {
            informational: Vec::new(),
            control: ControlData::Request {
                method,
                scheme,
                authority,
                path,
            },
            header: FieldSection::default(),
            content: Vec::new(),
            trailer: FieldSection::default(),
        }
    }

    #[must_use]
    pub fn response(status: StatusCode) -> Self {
        Self {
            informational: Vec::new(),
            control: ControlData::Response(status),
            header: FieldSection::default(),
            content: Vec::new(),
            trailer: FieldSection::default(),
        }
    }

    pub fn put_header(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.header.put(name, value);
    }

    pub fn put_trailer(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.trailer.put(name, value);
    }

    pub fn write_content(&mut self, d: impl AsRef<[u8]>) {
        self.content.extend_from_slice(d.as_ref());
    }

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

    #[cfg(feature = "http")]
    fn read_chunked<T, R>(r: &mut T) -> Res<Vec<u8>>
    where
        T: BorrowMut<R> + ?Sized,
        R: ReadSeek + ?Sized,
    {
        let mut content = Vec::new();
        loop {
            let mut line = read_line(r)?;
            if let Some(i) = index_of(SEMICOLON, &line) {
                std::mem::drop(line.split_off(i));
            }
            let count_str = String::from_utf8(line)?;
            let count = usize::from_str_radix(&count_str, 16)?;
            if count == 0 {
                return Ok(content);
            }
            let mut buf = vec![0; count];
            r.borrow_mut().read_exact(&mut buf)?;
            assert!(read_line(r)?.is_empty());
            content.append(&mut buf);
        }
    }

    #[cfg(feature = "http")]
    pub fn read_http<T, R>(r: &mut T) -> Res<Self>
    where
        T: BorrowMut<R> + ?Sized,
        R: ReadSeek + ?Sized,
    {
        let line = read_line(r)?;
        let mut control = ControlData::read_http(line)?;
        let mut informational = Vec::new();
        while let Some(status) = control.informational() {
            let fields = FieldSection::read_http(r)?;
            informational.push(InformationalResponse::new(status, fields));
            let line = read_line(r)?;
            control = ControlData::read_http(line)?;
        }

        let mut header = FieldSection::read_http(r)?;

        let (content, trailer) =
            if matches!(control.status().map(StatusCode::code), Some(204 | 304)) {
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
                    let cl_int = cl_str.parse::<usize>()?;
                    if cl_int > 0 {
                        content.resize(cl_int, 0);
                        r.borrow_mut().read_exact(&mut content)?;
                    }
                } else {
                    // Note that for a request, the spec states that the content is
                    // empty, but this just reads all input like for a response.
                    r.borrow_mut().read_to_end(&mut content)?;
                }
                (content, FieldSection::default())
            };

        header.strip_connection_headers();
        Ok(Self {
            informational,
            control,
            header,
            content,
            trailer,
        })
    }

    #[cfg(feature = "http")]
    pub fn write_http(&self, w: &mut impl io::Write) -> Res<()> {
        for info in &self.informational {
            ControlData::Response(info.status()).write_http(w)?;
            info.fields().write_http(w)?;
        }
        self.control.write_http(w)?;
        if !self.content.is_empty() {
            if self.trailer.is_empty() {
                write!(w, "Content-Length: {}\r\n", self.content.len())?;
            } else {
                w.write_all(b"Transfer-Encoding: chunked\r\n")?;
            }
        }
        self.header.write_http(w)?;

        if self.header.is_chunked() {
            write!(w, "{:x}\r\n", self.content.len())?;
            w.write_all(&self.content)?;
            w.write_all(b"\r\n0\r\n")?;
            self.trailer.write_http(w)?;
        } else {
            w.write_all(&self.content)?;
        }

        Ok(())
    }

    /// Read a BHTTP message.
    pub fn read_bhttp<T, R>(r: &mut T) -> Res<Self>
    where
        T: BorrowMut<R> + ?Sized,
        R: ReadSeek + ?Sized,
    {
        let t = read_varint(r)?.ok_or(Error::Truncated)?;
        let request = t == 0 || t == 2;
        let mode = match t {
            0 | 1 => Mode::KnownLength,
            2 | 3 => Mode::IndeterminateLength,
            _ => return Err(Error::InvalidMode),
        };

        let mut control = ControlData::read_bhttp(request, r)?;
        let mut informational = Vec::new();
        while let Some(status) = control.informational() {
            let fields = FieldSection::read_bhttp(mode, r)?;
            informational.push(InformationalResponse::new(status, fields));
            control = ControlData::read_bhttp(request, r)?;
        }
        let header = FieldSection::read_bhttp(mode, r)?;

        let mut content = read_vec(r)?.unwrap_or_default();
        if mode == Mode::IndeterminateLength && !content.is_empty() {
            loop {
                let mut extra = read_vec(r)?.unwrap_or_default();
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

    pub fn write_bhttp(&self, mode: Mode, w: &mut impl io::Write) -> Res<()> {
        write_varint(self.control.code(mode), w)?;
        for info in &self.informational {
            info.write_bhttp(mode, w)?;
        }
        self.control.write_bhttp(w)?;
        self.header.write_bhttp(mode, w)?;

        write_vec(&self.content, w)?;
        if mode == Mode::IndeterminateLength && !self.content.is_empty() {
            write_len(0, w)?;
        }
        self.trailer.write_bhttp(mode, w)?;
        Ok(())
    }
}

#[cfg(feature = "http")]
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut buf = Vec::new();
        self.write_http(&mut buf).map_err(|_| std::fmt::Error)?;
        write!(f, "{:?}", String::from_utf8_lossy(&buf))
    }
}
