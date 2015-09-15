use std::io::Read;
use std::ptr;

use libc::{c_int, size_t};

use byteorder;
use byteorder::{ReadBytesExt, BigEndian};

use gmp::mpz::{Mpz,mpz_srcptr};

pub trait FromSSH : Sized {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self>;
}

impl FromSSH for u8 {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    return reader.read_u8();
  }
}

impl FromSSH for bool {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    let result = try!(reader.read_u8());

    return Ok(result != 0);
  }
}

impl FromSSH for u32 {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    return reader.read_u32::<BigEndian>();
  }
}

impl FromSSH for Vec<u8> {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    let n = try!(u32::from_ssh(reader));

    let mut result = Vec::with_capacity(n as usize);
    try!(reader.take(n as u64).read_to_end(&mut result));
    return Ok(result);
  }
}

impl FromSSH for String {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    let n = try!(u32::from_ssh(reader));

    let mut result = String::with_capacity(n as usize);
    try!(reader.take(n as u64).read_to_string(&mut result));
    return Ok(result);
  }
}

#[link(name = "gmp")]
extern "C" {
  fn __gmpz_import(rop: mpz_srcptr, count: size_t, order: c_int, size: size_t, endian: c_int, nails: size_t, op: *const u8);
}

impl FromSSH for Mpz {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    let mut content: Vec<u8> = try!(FromSSH::from_ssh(reader));

    if content.len() == 0 {
      return Ok(From::from(0));
    }

    let negative = content.first().unwrap() & 0x80 == 0x80;
    let result = Mpz::new_reserve(content.len() * 8);

    if negative {
      for i in 0 .. content.len() {
        content[i] = !content[i];
      }
    }

    unsafe {
      __gmpz_import(&result.mpz, content.len() as u64, 1, 1, 1, 0, content.as_ptr());
    }

    if negative {
      return Ok(-Mpz::one() - result);
    } else {
      return Ok(result);
    }
  }
}
