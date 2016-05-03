use std::io;
use std::io::{Read, Write};

use std::iter::FromIterator;

use num::One;
use num::traits::Signed;

use num::BigInt;
use num::bigint::Sign;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub trait SSHRead : Read {
  fn read_n_into_buffer(&mut self, buffer: &mut [u8]) {
    let mut n = 0;

    while n < buffer.len() {
        match self.read(&mut buffer[n..]) {
            Ok(0) => panic!("Couldn't read!"),
            Ok(i) => n += i,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(_) => panic!("Unknown error!")
        }
    }
  }

  fn read_n(&mut self, n: u32) -> Vec<u8> {
    let mut buffer = Vec::new();

    self.take(n as u64).read_to_end(&mut buffer).unwrap();

    return buffer;
  }

  fn read_bool(&mut self) -> bool {
    return self.read_u8().unwrap() != 0;
  }

  fn read_uint32(&mut self) -> u32 {
    return self.read_u32::<BigEndian>().unwrap();
  }

  fn read_string(&mut self) -> String {
    let n = self.read_u32::<BigEndian>().unwrap();

    let mut string = String::new();
    self.take(n as u64).read_to_string(&mut string).unwrap();
    return string;
  }

  fn read_binary_string(&mut self) -> Vec<u8> {
    let n = self.read_u32::<BigEndian>().unwrap();
    return self.read_n(n);
  }

  fn read_mpint(&mut self) -> BigInt {
    let mut value = self.read_binary_string();

    if value.first().unwrap() & 0x80 == 0x80 {
      for i in 0 .. value.len() {
        value[i] = !value[i];
      }

      let result: BigInt = BigInt::from_bytes_be(Sign::Minus, &value[..]) - &One::one();

      return result;
    } else {
      return BigInt::from_bytes_be(Sign::Plus, &value[..]);
    }
  }

  fn read_name_list(&mut self) -> Vec<String> {
    let string = self.read_string();
    return Vec::from_iter(string.split(',').map(|x| { String::from(x) }));
  }
}

impl<T: Read> SSHRead for T {}

pub trait SSHWrite : Write {
  fn write_bool(&mut self, v: bool) {
    self.write_u8(if v { 1 } else { 0 }).unwrap();
  }

  fn write_uint32(&mut self, v: u32) {
    self.write_u32::<BigEndian>(v).unwrap();
  }

  fn write_string(&mut self, str: &str) {
    self.write_binary_string(str.as_bytes());
  }

  fn write_binary_string(&mut self, str: &[u8]) {
    self.write_u32::<BigEndian>(str.len() as u32).unwrap();
    self.write_all(str).unwrap();
  }

  fn write_mpint(&mut self, v: &BigInt) {
    if v.is_negative() {
      let v: BigInt = v + &One::one();
      let (_, mut data) = v.to_bytes_be();

      let length = data.len();

      if data.first().unwrap() & 0x80 == 0x80 {
        for i in 0 .. length {
          data[i as usize] = !data[i as usize];
        }

        self.write_u32::<BigEndian>(length as u32 + 1).unwrap();
        self.write_u8(0xFF).unwrap();
        self.write_all(&data[..]).unwrap();
      } else {
        for i in 0 .. length {
          data[i] = !data[i];
        }

        self.write_u32::<BigEndian>(length as u32).unwrap();
        self.write_all(&data[..]).unwrap();
      }
    } else {
      let (_, data) = v.to_bytes_be();

      let length = data.len() as u32;

      if data.first().unwrap() & 0x80 == 0x80 {
        self.write_u32::<BigEndian>(length + 1).unwrap();
        self.write_u8(0).unwrap();
        self.write_all(&data[..]).unwrap();
      } else {
        self.write_u32::<BigEndian>(length).unwrap();
        self.write_all(&data[..]).unwrap();
      }
    }
  }

  fn write_name_list(&mut self, name_list: &Vec<String>) {
    self.write_string(name_list.join(",").as_str());
  }
}

impl<T: Write> SSHWrite for T {}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use num::bigint::ToBigInt;

  use super::{SSHWrite, SSHRead};

  macro_rules! test_roundtrip {
    ($a:expr, $b:expr) => {{
      let a = $a.to_bigint().unwrap();
      let b = $b;

      let mut writer = Cursor::new(Vec::new());

      writer.write_mpint(&a);

      let v = writer.into_inner();

      assert_eq!(v, b);

      let mut reader = Cursor::new(v);

      assert_eq!(reader.read_mpint(), a);
    }};
  }

  #[test]
  fn test_mpint_one() {
    test_roundtrip!(1, vec![0x00, 0x00, 0x00, 0x01, 0x01]);
  }

  #[test]
  fn test_write_mpint_ff() {
    test_roundtrip!(0xFF, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0xFF]);
  }

  #[test]
  fn test_write_mpint_zero() {
    test_roundtrip!(0, vec![0x00, 0x00, 0x00, 0x01, 0x00]);
  }

  #[test]
  fn test_write_mpint_negative_one() {
    test_roundtrip!(-1, vec![0x00, 0x00, 0x00, 0x01, 0xFF]);
  }

  #[test]
  fn test_write_mpint_negative_ff() {
    test_roundtrip!(-0xFF, vec![0x00, 0x00, 0x00, 0x02, 0xFF, 0x01]);
  }

  #[test]
  fn test_mpint_ffff() {
    test_roundtrip!( 0xFFFFFFFFi64, vec![0x00, 0x00, 0x00, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    test_roundtrip!(-0xFFFFFFFFi64, vec![0x00, 0x00, 0x00, 0x05, 0xFF, 0x00, 0x00, 0x00, 0x01]);
  }

  #[test]
  fn test_from_quicktest() {
    test_roundtrip!(-35, vec![0x00, 0x00, 0x00, 0x01, 0xDD]);
    test_roundtrip!(149, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x95]);
    test_roundtrip!(36412, vec![0x00, 0x00, 0x00, 0x03, 0x00, 0x8E, 0x3C]);
  }
}
