#![feature(libc)]
#![feature(convert)]

#![cfg_attr(test, feature(plugin))]
#![cfg_attr(test, plugin(quickcheck_macros))]

extern crate num;
extern crate rand;
extern crate byteorder;

#[cfg(test)]
extern crate quickcheck;

use std::io::{Read, Write};
use std::net::TcpStream;

use byteorder::{ReadBytesExt, WriteBytesExt};

pub mod hash;

pub mod transport {
  pub mod ssh_socket;
  pub mod ssh_transport;
}

mod sshio;
mod packets {
  pub mod group_exchange;
  pub mod disconnect;
  pub mod key_exchange;
}

use sshio::SSHRead;

use packets::disconnect;
use packets::group_exchange;
use packets::key_exchange;

fn main() {
  let mut tcp_socket = TcpStream::connect("127.0.0.1:22").unwrap();

  let reader = &mut tcp_socket.try_clone().unwrap() as &mut Read;
  let writer = &mut tcp_socket as &mut Write;

  let mut socket = transport::ssh_socket::Socket::new(reader, writer);
  let mut transport = transport::ssh_transport::Transport::new(&mut socket);

  println!("Packet!: {:?}", transport.read_packet());
}

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