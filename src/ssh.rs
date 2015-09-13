#![feature(libc)]
#![feature(convert)]

#![cfg_attr(test, feature(plugin))]
#![cfg_attr(test, plugin(quickcheck_macros))]

//! # ssh.rs: an SSH implementation in Rust
//!
//! There are many things to say about safety in memory usage.
//! This implementation tries to avoid those issues by mostly
//! using Rust's safe constructs.
//!
//! Warning: Everything is quite slow.
//!
//! ![sshlogo](http://neophob.com/wp-content/uploads/2010/05/sshlogo.png)

extern crate num;
extern crate rand;
extern crate byteorder;

#[cfg(test)]
extern crate quickcheck;

use std::io::{Read, Write};

use std::net::TcpStream;

/// The `hash` module defines ways of hashing and digesting.
pub mod hash;

/// The `transport` module defines SSH socket and transport details.
pub mod transport {
  /// Reads and writes SSH messages.
  pub mod ssh_socket;
  /// The SSH conversation
  pub mod ssh_transport;
}

/// SSH I/O
mod sshio;
/// SSH-related Packets
mod packets;

fn main() {
  let mut tcp_socket = TcpStream::connect("127.0.0.1:9001").unwrap();

  let reader = &mut tcp_socket.try_clone().unwrap() as &mut Read;
  let writer = &mut tcp_socket as &mut Write;

  let mut socket = transport::ssh_socket::Socket::new(reader, writer);
  let mut transport = transport::ssh_transport::Transport::new(&mut socket);

  println!("Packet!: {:?}", transport.read());
}
