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

pub mod hash;

pub mod transport {
  pub mod ssh_socket;
  pub mod ssh_transport;
}

mod sshio;
mod packets;

fn main() {
  let mut tcp_socket = TcpStream::connect("127.0.0.1:22").unwrap();

  let reader = &mut tcp_socket.try_clone().unwrap() as &mut Read;
  let writer = &mut tcp_socket as &mut Write;

  let mut socket = transport::ssh_socket::Socket::new(reader, writer);
  let mut transport = transport::ssh_transport::Transport::new(&mut socket);

  println!("Packet!: {:?}", transport.read_packet());
}
