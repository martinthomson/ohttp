use libc::{c_int, size_t};

#[link(name = "azguestattestation")]
extern {
    fn get_attestation_token(app_data: *const u8, pcr_sel: u32, jwt: *mut u8,  jwt_len: *mut size_t, endpoint_url: *const u8) -> c_int;
}

pub fn attest(data: &[u8], pcrs: u32, endpoint_url: &str) -> Option<Vec<u8>> {
    unsafe {
        let url_ptr: *const u8 = endpoint_url.as_ptr();
        let mut dstlen = 32*1024;
        let mut dst = Vec::with_capacity(dstlen as usize);
        let pdst = dst.as_mut_ptr();
        let res = get_attestation_token(data.as_ptr(), pcrs, pdst, &mut dstlen, url_ptr);
        dst.set_len(dstlen as usize);
        if res == 0 {
            Some(dst)
         } else {
            None
         }
    }
}