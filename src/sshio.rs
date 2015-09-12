use std::io;
use std::io::{Read, Write};
use std::io::Cursor;

use std::iter::FromIterator;

use num::One;
use num::traits::Signed;

use num::BigInt;
use num::bigint::Sign;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use SSHPacket;

use packets::disconnect;
use packets::group_exchange;
use packets::key_exchange;

use gmp::mpz::Mpz;

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

  fn read_mpint(&mut self) -> Mpz {
    let mut value = self.read_binary_string();
    return From::from(&mut value[..]);
  }

  fn read_name_list(&mut self) -> Vec<String> {
    let string = self.read_string();
    return Vec::from_iter(string.split(',').map(|x| { String::from(x) }));
  }

  fn read_raw_ssh_packet(&mut self, mac_length: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>){
    let packet_length = self.read_u32::<BigEndian>().unwrap();
    let padding_length = self.read_u8().unwrap() as u32;

    let payload = self.read_n(packet_length - padding_length - 1);
    let padding = self.read_n(padding_length);
    let mac = self.read_n(mac_length);

    return (payload, padding, mac);
  }

  fn read_packet(&mut self) -> SSHPacket {
    let (payload, _, _) = self.read_raw_ssh_packet(0);

    let reader = &mut Cursor::new(&payload[1 ..]);

    return match payload[0] {
      1 => SSHPacket::Disconnect(disconnect::Disconnect::read(reader)),
      20 => SSHPacket::KeyExchange(key_exchange::KeyExchangeInit::read(reader)),
      21 => SSHPacket::NewKeys(key_exchange::NewKeys::read(reader)),
      31 => SSHPacket::GroupExchangeGroup(group_exchange::Group::read(reader)),
      32 => SSHPacket::GroupExchangeInit(group_exchange::Init::read(reader)),
      33 => SSHPacket::GroupExchangeReply(group_exchange::Reply::read(reader)),
      34 => SSHPacket::GroupExchangeRequest(group_exchange::Request::read(reader)),
      _ => {
        println!("{:?}", payload);
        panic!("Oh noes");
      }
    }
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

  fn write_mpint(&mut self, v: &Mpz) {
    let value: Vec<u8> = Into::into(v);
    self.write_binary_string(&value);
  }

  fn write_name_list(&mut self, name_list: &Vec<String>) {
    self.write_string(name_list.join(",").as_str());
  }

  fn write_raw_ssh_packet(&mut self, payload: &[u8]) {
    let padding_length = 8 - (5 + payload.len()) % 8;
    let padding_length = if padding_length < 4 { padding_length + 8 } else { padding_length };

    self.write_u32::<BigEndian>((payload.len() + padding_length + 1) as u32).unwrap();
    self.write_u8(padding_length as u8).unwrap();

    let padding = vec![0u8; padding_length];

    self.write_all(payload).unwrap();
    self.write_all(&padding[..]).unwrap();
    // TODO: MAC
  }

  fn write_packet(&mut self, packet: &SSHPacket) {
    let mut writer = Cursor::new(Vec::new());

    match packet {
      &SSHPacket::Disconnect(ref p) => {
        writer.write_u8(1).unwrap();
        p.write(&mut writer);
      }
      &SSHPacket::KeyExchange(ref p) => {
        writer.write_u8(20).unwrap();
        p.write(&mut writer);
      }
      &SSHPacket::NewKeys(ref p) => {
        writer.write_u8(21).unwrap();
        p.write(&mut writer);
      }
      &SSHPacket::GroupExchangeGroup(ref p) => {
        writer.write_u8(31).unwrap();
        p.write(&mut writer);
      }
      &SSHPacket::GroupExchangeInit(ref p) => {
        writer.write_u8(32).unwrap();
        p.write(&mut writer);
      }
      &SSHPacket::GroupExchangeReply(ref p) => {
        writer.write_u8(33).unwrap();
        p.write(&mut writer);
      }
      &SSHPacket::GroupExchangeRequest(ref p) => {
        writer.write_u8(34).unwrap();
        p.write(&mut writer);
      }
    }

    let payload = writer.into_inner();

    self.write_raw_ssh_packet(&payload[..]);
  }
}

impl<T: Write> SSHWrite for T {}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use super::{SSHWrite, SSHRead};

  macro_rules! test_roundtrip {
    ($a:expr, $b:expr) => {{
      let a = From::from($a);
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