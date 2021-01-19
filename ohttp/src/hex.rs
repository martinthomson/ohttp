pub fn hex(buf: &[u8]) -> String {
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
