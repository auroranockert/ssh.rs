extern crate libc;

use std::default::Default;

pub trait Hash {
  fn update(&mut self, input: &[u8]);
  fn digest(&mut self) -> Vec<u8>;
}

#[repr(C)] struct MD5_CTX { content: [u8; 92] }

impl Default for MD5_CTX {
  fn default() -> MD5_CTX {
    return MD5_CTX { content: [0; 92] };
  }
}
#[repr(C)] struct SHA_CTX { content: [u8; 96] }

impl Default for SHA_CTX {
  fn default() -> SHA_CTX {
    return SHA_CTX { content: [0; 96] };
  }
}
#[repr(C)] struct SHA256_CTX { content: [u8; 112] }

impl Default for SHA256_CTX {
  fn default() -> SHA256_CTX {
    return SHA256_CTX { content: [0; 112] };
  }
}
#[repr(C)] struct SHA512_CTX { content: [u8; 216] }

impl Default for SHA512_CTX {
  fn default() -> SHA512_CTX {
    return SHA512_CTX { content: [0; 216] };
  }
}

#[link(name = "crypto")]
extern {
  fn MD5_Init(context: *mut MD5_CTX) -> libc::c_int;
  fn MD5_Update(context: *mut MD5_CTX, data: *const u8, length: libc::c_ulong) -> libc::c_int;
  fn MD5_Final(result: *mut u8, context: *mut MD5_CTX) -> libc::c_int;
}

pub struct MD5 { context: MD5_CTX }

impl MD5 {
  pub fn new() -> MD5 {
    let mut context: MD5_CTX = Default::default();

    if unsafe { MD5_Init(&mut context) } != 1 {
      panic!("Failed to initialize MD5 state");
    }

    return MD5 { context: context }
  }
}

impl Hash for MD5 {
  fn update(&mut self, input: &[u8]) {
    let err = unsafe { MD5_Update(&mut self.context, input.as_ptr(), input.len() as u64) };

    if err != 1 { panic!("Failed to update MD5 state") }
  }

  fn digest(&mut self) -> Vec<u8> {
    let mut result = [0u8; 16];

    let err = unsafe { MD5_Final((&mut result[..]).as_mut_ptr(), &mut self.context) };

    if err != 1 { panic!("Failed to finalize MD5 state") }

    return result.to_vec();
  }
}

#[test]
fn calculates_null_md5_hash() {
  let mut hash = MD5::new();

  let null_hash = &[0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e];
  let digest = hash.digest();

  for i in 0 .. null_hash.len() {
    assert_eq!(digest[i], null_hash[i]);
  }
}

#[test]
fn calculates_foxy_md5_hash() {
  let mut hash = MD5::new();

  hash.update(b"The quick brown fox jumps over the lazy dog");

  let foxy_hash = &[0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6];
  let digest = hash.digest();

  for i in 0 .. foxy_hash.len() {
    assert_eq!(digest[i], foxy_hash[i]);
  }
}

#[link(name = "crypto")]
extern {
  fn SHA1_Init(context: *mut SHA_CTX) -> libc::c_int;
  fn SHA1_Update(context: *mut SHA_CTX, data: *const u8, length: libc::c_ulong) -> libc::c_int;
  fn SHA1_Final(result: *mut u8, context: *mut SHA_CTX) -> libc::c_int;
}

pub struct SHA1 { context: SHA_CTX }

impl SHA1 {
  pub fn new() -> SHA1 {
    let mut context: SHA_CTX = Default::default();

    if unsafe { SHA1_Init(&mut context) } != 1 {
      panic!("Failed to initialize SHA1 state");
    }

    return SHA1 { context: context }
  }
}

impl Hash for SHA1 {
  fn update(&mut self, input: &[u8]) {
    let err = unsafe { SHA1_Update(&mut self.context, input.as_ptr(), input.len() as u64) };

    if err != 1 { panic!("Failed to update SHA1 state") }
  }

  fn digest(&mut self) -> Vec<u8> {
    let mut result = [0u8; 20];

    let err = unsafe { SHA1_Final((&mut result[..]).as_mut_ptr(), &mut self.context) };

    if err != 1 { panic!("Failed to finalize SHA1 state") }

    return result.to_vec();
  }
}

#[test]
fn calculates_null_sha1_hash() {
  let mut hash = SHA1::new();

  let null_hash = &[0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09];
  let digest = hash.digest();

  for i in 0 .. null_hash.len() {
    assert_eq!(digest[i], null_hash[i]);
  }
}

#[test]
fn calculates_foxy_sha1_hash() {
  let mut hash = SHA1::new();

  hash.update(b"The quick brown fox jumps over the lazy dog");

  let foxy_hash = &[0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12];
  let digest = hash.digest();

  for i in 0 .. foxy_hash.len() {
    assert_eq!(digest[i], foxy_hash[i]);
  }
}

#[link(name = "crypto")]
extern {
  fn SHA224_Init(context: *mut SHA256_CTX) -> libc::c_int;
  fn SHA224_Update(context: *mut SHA256_CTX, data: *const u8, length: libc::c_ulong) -> libc::c_int;
  fn SHA224_Final(result: *mut u8, context: *mut SHA256_CTX) -> libc::c_int;
}

pub struct SHA224 { context: SHA256_CTX }

impl SHA224 {
  pub fn new() -> SHA224 {
    let mut context: SHA256_CTX = Default::default();

    if unsafe { SHA224_Init(&mut context) } != 1 {
      panic!("Failed to initialize SHA224 state");
    }

    return SHA224 { context: context }
  }
}

impl Hash for SHA224 {
  fn update(&mut self, input: &[u8]) {
    let err = unsafe { SHA224_Update(&mut self.context, input.as_ptr(), input.len() as u64) };

    if err != 1 { panic!("Failed to update SHA224 state") }
  }

  fn digest(&mut self) -> Vec<u8> {
    let mut result = [0u8; 28];

    let err = unsafe { SHA224_Final((&mut result[..]).as_mut_ptr(), &mut self.context) };

    if err != 1 { panic!("Failed to finalize SHA224 state") }

    return result.to_vec();
  }
}

#[test]
fn calculates_null_sha224_hash() {
  let mut hash = SHA224::new();

  let null_hash = &[0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f];
  let digest = hash.digest();

  for i in 0 .. null_hash.len() {
    assert_eq!(digest[i], null_hash[i]);
  }
}

#[test]
fn calculates_foxy_sha224_hash() {
  let mut hash = SHA224::new();

  hash.update(b"The quick brown fox jumps over the lazy dog");

  let foxy_hash = &[0x73, 0x0e, 0x10, 0x9b, 0xd7, 0xa8, 0xa3, 0x2b, 0x1c, 0xb9, 0xd9, 0xa0, 0x9a, 0xa2, 0x32, 0x5d, 0x24, 0x30, 0x58, 0x7d, 0xdb, 0xc0, 0xc3, 0x8b, 0xad, 0x91, 0x15, 0x25];
  let digest = hash.digest();

  for i in 0 .. foxy_hash.len() {
    assert_eq!(digest[i], foxy_hash[i]);
  }
}

#[link(name = "crypto")]
extern {
  fn SHA256_Init(context: *mut SHA256_CTX) -> libc::c_int;
  fn SHA256_Update(context: *mut SHA256_CTX, data: *const u8, length: libc::c_ulong) -> libc::c_int;
  fn SHA256_Final(result: *mut u8, context: *mut SHA256_CTX) -> libc::c_int;
}

pub struct SHA256 { context: SHA256_CTX }

impl SHA256 {
  pub fn new() -> SHA256 {
    let mut context: SHA256_CTX = Default::default();

    if unsafe { SHA256_Init(&mut context) } != 1 {
      panic!("Failed to initialize SHA256 state");
    }

    return SHA256 { context: context }
  }
}

impl Hash for SHA256 {
  fn update(&mut self, input: &[u8]) {
    let err = unsafe { SHA256_Update(&mut self.context, input.as_ptr(), input.len() as u64) };

    if err != 1 { panic!("Failed to update SHA256 state") }
  }

  fn digest(&mut self) -> Vec<u8> {
    let mut result = [0u8; 32];

    let err = unsafe { SHA256_Final((&mut result[..]).as_mut_ptr(), &mut self.context) };

    if err != 1 { panic!("Failed to finalize SHA256 state") }

    return result.to_vec();
  }
}

#[test]
fn calculates_null_sha256_hash() {
  let mut hash = SHA256::new();

  let null_hash = &[0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55];
  let digest = hash.digest();

  for i in 0 .. null_hash.len() {
    assert_eq!(digest[i], null_hash[i]);
  }
}

#[test]
fn calculates_foxy_sha256_hash() {
  let mut hash = SHA256::new();

  hash.update(b"The quick brown fox jumps over the lazy dog");

  let foxy_hash = &[0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92];
  let digest = hash.digest();

  for i in 0 .. foxy_hash.len() {
    assert_eq!(digest[i], foxy_hash[i]);
  }
}

#[link(name = "crypto")]
extern {
  fn SHA384_Init(context: *mut SHA512_CTX) -> libc::c_int;
  fn SHA384_Update(context: *mut SHA512_CTX, data: *const u8, length: libc::c_ulong) -> libc::c_int;
  fn SHA384_Final(result: *mut u8, context: *mut SHA512_CTX) -> libc::c_int;
}

pub struct SHA384 { context: SHA512_CTX }

impl SHA384 {
  pub fn new() -> SHA384 {
    let mut context: SHA512_CTX = Default::default();

    if unsafe { SHA384_Init(&mut context) } != 1 {
      panic!("Failed to initialize SHA384 state");
    }

    return SHA384 { context: context }
  }
}

impl Hash for SHA384 {
  fn update(&mut self, input: &[u8]) {
    let err = unsafe { SHA384_Update(&mut self.context, input.as_ptr(), input.len() as u64) };

    if err != 1 { panic!("Failed to update SHA384 state") }
  }

  fn digest(&mut self) -> Vec<u8> {
    let mut result = [0u8; 48];

    let err = unsafe { SHA384_Final((&mut result[..]).as_mut_ptr(), &mut self.context) };

    if err != 1 { panic!("Failed to finalize SHA384 state") }

    return result.to_vec();
  }
}

#[test]
fn calculates_null_sha384_hash() {
  let mut hash = SHA384::new();

  let null_hash = &[0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b];
  let digest = hash.digest();

  for i in 0 .. null_hash.len() {
    assert_eq!(digest[i], null_hash[i]);
  }
}

#[test]
fn calculates_foxy_sha384_hash() {
  let mut hash = SHA384::new();

  hash.update(b"The quick brown fox jumps over the lazy dog");

  let foxy_hash = &[0xca, 0x73, 0x7f, 0x10, 0x14, 0xa4, 0x8f, 0x4c, 0x0b, 0x6d, 0xd4, 0x3c, 0xb1, 0x77, 0xb0, 0xaf, 0xd9, 0xe5, 0x16, 0x93, 0x67, 0x54, 0x4c, 0x49, 0x40, 0x11, 0xe3, 0x31, 0x7d, 0xbf, 0x9a, 0x50, 0x9c, 0xb1, 0xe5, 0xdc, 0x1e, 0x85, 0xa9, 0x41, 0xbb, 0xee, 0x3d, 0x7f, 0x2a, 0xfb, 0xc9, 0xb1];
  let digest = hash.digest();

  for i in 0 .. foxy_hash.len() {
    assert_eq!(digest[i], foxy_hash[i]);
  }
}

#[link(name = "crypto")]
extern {
  fn SHA512_Init(context: *mut SHA512_CTX) -> libc::c_int;
  fn SHA512_Update(context: *mut SHA512_CTX, data: *const u8, length: libc::c_ulong) -> libc::c_int;
  fn SHA512_Final(result: *mut u8, context: *mut SHA512_CTX) -> libc::c_int;
}

pub struct SHA512 { context: SHA512_CTX }

impl SHA512 {
  pub fn new() -> SHA512 {
    let mut context: SHA512_CTX = Default::default();

    if unsafe { SHA512_Init(&mut context) } != 1 {
      panic!("Failed to initialize SHA512 state");
    }

    return SHA512 { context: context }
  }
}

impl Hash for SHA512 {
  fn update(&mut self, input: &[u8]) {
    let err = unsafe { SHA512_Update(&mut self.context, input.as_ptr(), input.len() as u64) };

    if err != 1 { panic!("Failed to update SHA512 state") }
  }

  fn digest(&mut self) -> Vec<u8> {
    let mut result = [0u8; 64];

    let err = unsafe { SHA512_Final((&mut result[..]).as_mut_ptr(), &mut self.context) };

    if err != 1 { panic!("Failed to finalize SHA512 state") }

    return result.to_vec();
  }
}

#[test]
fn calculates_null_sha512_hash() {
  let mut hash = SHA512::new();

  let null_hash = &[0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e];
  let digest = hash.digest();

  for i in 0 .. null_hash.len() {
    assert_eq!(digest[i], null_hash[i]);
  }
}

#[test]
fn calculates_foxy_sha512_hash() {
  let mut hash = SHA512::new();

  hash.update(b"The quick brown fox jumps over the lazy dog");

  let foxy_hash = &[0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69, 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88, 0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39, 0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6, 0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f, 0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6];
  let digest = hash.digest();

  for i in 0 .. foxy_hash.len() {
    assert_eq!(digest[i], foxy_hash[i]);
  }
}

