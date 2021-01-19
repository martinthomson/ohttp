use crate::err::Res;
use std::convert::TryFrom;
use std::io;

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
pub fn write_varint(v: impl Into<u64>, w: &mut impl io::Write) -> Res<()> {
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
pub fn write_len(len: usize, w: &mut impl io::Write) -> Res<()> {
    write_varint(u64::try_from(len).unwrap(), w)
}

#[cfg(feature = "write-bhttp")]
pub fn write_vec(v: &[u8], w: &mut impl io::Write) -> Res<()> {
    write_varint(u64::try_from(v.len()).unwrap(), w)?;
    w.write_all(v)?;
    Ok(())
}

#[cfg(feature = "read-bhttp")]
pub fn read_varint(r: &mut impl io::BufRead) -> Res<u64> {
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
pub fn read_vec(r: &mut impl io::BufRead) -> Res<Vec<u8>> {
    let len = read_varint(r)?;
    let mut v = vec![0; usize::try_from(len).unwrap()];
    r.read_exact(&mut v)?;
    Ok(v)
}
