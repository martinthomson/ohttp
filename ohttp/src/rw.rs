use crate::err::Error;
use crate::err::Res;
use std::convert::TryFrom;
use std::io;

#[allow(clippy::cast_possible_truncation)]
pub fn write_uint(n: usize, v: impl Into<u64>, w: &mut impl io::Write) -> Res<()> {
    let v = v.into();
    assert!(n > 0 && n < std::mem::size_of::<u64>());
    for i in 0..n {
        w.write_all(&[((v >> (8 * (n - i - 1))) & 0xff) as u8])?;
    }
    Ok(())
}

pub fn write_uvec(n: usize, v: &[u8], w: &mut impl io::Write) -> Res<()> {
    write_uint(n, u64::try_from(v.len()).unwrap(), w)?;
    w.write_all(v)?;
    Ok(())
}

pub fn read_uint(n: usize, r: &mut impl io::BufRead) -> Res<u64> {
    let mut buf = [0; 7];
    let count = r.read(&mut buf[..n])?;
    if count < n {
        return Err(Error::Truncated);
    }
    let mut v = 0;
    for i in &buf[..n] {
        v = (v << 8) | u64::from(*i);
    }
    Ok(v)
}

pub fn read_uvec(n: usize, r: &mut impl io::BufRead) -> Res<Vec<u8>> {
    let len = read_uint(n, r)?;
    let mut v = vec![0; usize::try_from(len).unwrap()];
    r.read_exact(&mut v)?;
    Ok(v)
}
