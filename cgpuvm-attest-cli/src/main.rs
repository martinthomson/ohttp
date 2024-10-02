use cgpuvm_attest::attest;

pub fn main() {
    let s = "{\"a\":1}";
    let Some(token) = attest(s.as_bytes(), 0xffff) else {panic!("Failed to get MAA token")};
    println!("Got MAA token: {}", String::from_utf8(token).unwrap());
}
