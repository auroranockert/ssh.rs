pub mod group_exchange;
pub mod disconnect;
pub mod key_exchange;

use std::io::{Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};

#[derive(Debug)]
pub enum SSHPacket {
  Disconnect(disconnect::Disconnect),
  KeyExchange(key_exchange::KeyExchangeInit),
  NewKeys(key_exchange::NewKeys),
  GroupExchangeRequest(group_exchange::Request),
  GroupExchangeGroup(group_exchange::Group),
  GroupExchangeInit(group_exchange::Init),
  GroupExchangeReply(group_exchange::Reply)
}

impl SSHPacket {
  pub fn read(reader: &mut Read) -> SSHPacket {
    let t = reader.read_u8().unwrap();

    return match t {
      1 => SSHPacket::Disconnect(disconnect::Disconnect::read(reader)),
      20 => SSHPacket::KeyExchange(key_exchange::KeyExchangeInit::read(reader)),
      21 => SSHPacket::NewKeys(key_exchange::NewKeys::read(reader)),
      31 => SSHPacket::GroupExchangeGroup(group_exchange::Group::read(reader)),
      32 => SSHPacket::GroupExchangeInit(group_exchange::Init::read(reader)),
      33 => SSHPacket::GroupExchangeReply(group_exchange::Reply::read(reader)),
      34 => SSHPacket::GroupExchangeRequest(group_exchange::Request::read(reader)),
      _ => {
        panic!(format!("Oh noes, unknown packet type {:?}", t));
      }
    }
  }

  pub fn write(&self, writer: &mut Write) {
    match self {
      &SSHPacket::Disconnect(ref p) => {
        writer.write_u8(1).unwrap();
        p.write(writer);
      }
      &SSHPacket::KeyExchange(ref p) => {
        writer.write_u8(20).unwrap();
        p.write(writer);
      }
      &SSHPacket::NewKeys(ref p) => {
        writer.write_u8(21).unwrap();
        p.write(writer);
      }
      &SSHPacket::GroupExchangeGroup(ref p) => {
        writer.write_u8(31).unwrap();
        p.write(writer);
      }
      &SSHPacket::GroupExchangeInit(ref p) => {
        writer.write_u8(32).unwrap();
        p.write(writer);
      }
      &SSHPacket::GroupExchangeReply(ref p) => {
        writer.write_u8(33).unwrap();
        p.write(writer);
      }
      &SSHPacket::GroupExchangeRequest(ref p) => {
        writer.write_u8(34).unwrap();
        p.write(writer);
      }
    }
  }
}
