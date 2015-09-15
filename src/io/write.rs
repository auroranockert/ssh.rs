use std::io::Write;
use std::ptr;

use libc::{c_int, size_t};

use byteorder;
use byteorder::WriteBytesExt;

use gmp::mpz::{Mpz, mpz_srcptr};

pub trait ToSSH {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()>;
}

impl ToSSH for u8 {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    return writer.write_u8(*self);
  }
}

impl ToSSH for bool {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    return if *self {
      1u8
    } else {
      0u8
    }.to_ssh(writer);
  }
}

impl ToSSH for u32 {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    return writer.write_u32::<byteorder::BigEndian>(*self);
  }
}

impl ToSSH for [u8] {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    try!((self.len() as u32).to_ssh(writer));

    return writer.write_all(self).map_err(From::from);
  }
}

impl ToSSH for str {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    return self.as_bytes().to_ssh(writer);
  }
}

impl ToSSH for Vec<String> {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    return self.join(",").as_str().to_ssh(writer);
  }
}

#[link(name = "gmp")]
extern "C" {
  fn __gmpz_export(rop: *mut u8, countp: *mut size_t, order: c_int, size: size_t, endian: c_int, nails: size_t, op: mpz_srcptr);
}

impl ToSSH for Mpz {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    let n = self.bit_length();

    if self.is_zero() {
      return 0u32.to_ssh(writer);
    }

    let bytes = (n + 7) / 8;
    let extra_byte = if n % 8 == 0 { 1 } else { 0 };
    let total_bytes = bytes + extra_byte;
    // TODO: Check for 32-bit overflow

    let mut data = Vec::with_capacity(total_bytes);

    let negative = self < &From::from(0);

    let number = if negative {
      if extra_byte != 0 { data.push(0xFF) };

      let complement: Mpz = From::from(256);
      let complement: Mpz = complement.pow(bytes as u32);
      let complement: Mpz = complement - &From::from(1);

      (self.abs() - &From::from(1)) ^ complement
    } else {
      if extra_byte != 0 { data.push(0x0) };

      self.clone()
    };

    let missing_bytes = bytes - (number.bit_length() + 7) / 8;

    for _ in 0 .. missing_bytes {
      data.push(0x00);
    }

    unsafe {
      __gmpz_export(data.get_unchecked_mut(extra_byte + missing_bytes) as *mut u8, ptr::null_mut(), 1, 1, 1, 0, &number.mpz);
      data.set_len(total_bytes);
    }

    return data.to_ssh(writer);
  }
}
