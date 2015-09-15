#![feature(libc)]
#![feature(convert)]
#![feature(clone_from_slice)]

#![cfg_attr(test, feature(plugin))]
#![cfg_attr(test, plugin(quickcheck_macros))]

extern crate gmp;
extern crate rand;
extern crate libc;
extern crate crypto;
extern crate byteorder;

#[cfg(test)]
extern crate quickcheck;

use std::io::{Read, Write};

use std::net::TcpStream;

pub mod io;
pub mod cryptography {
  pub mod mac;
  pub mod encrypter;
  pub mod decrypter;
}

mod packets;

pub mod transport {
  pub mod ssh_socket;
  pub mod ssh_transport;
}

fn main() {
  let mut tcp_socket = TcpStream::connect("127.0.0.1:22").unwrap();

  let reader = &mut tcp_socket.try_clone().unwrap() as &mut Read;
  let writer = &mut tcp_socket as &mut Write;

  let mut socket = transport::ssh_socket::Socket::new(reader, writer);
  let mut transport = transport::ssh_transport::Transport::new(&mut socket, false);

  // match transport.read() {
  //   packets::SSHPacket::Ignore(k) => println!("{:?}", k),
  //   pkt => panic!(format!("TODO: {:?}", pkt))
  // }
  // 
  // println!("Here3");
  // 
  // let c_kex = transport.start_rekey();
  // 
  // println!("Here4");
  // 
  // let s_kex = match transport.read() {
  //   packets::SSHPacket::KeyExchange(k) => k,
  //   pkt => panic!(format!("FIXME: Unhandled message during key exchange ({:?})", pkt))
  // };
  // 
  // transport.rekey(&c_kex, &s_kex);

  println!("Packet!: {:?}", transport.read().unwrap());
}
