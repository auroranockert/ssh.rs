//FIXME unused #![feature(libc)]
//FIXME unused #![feature(convert)]

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
//! <form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_top">
//! <input type="hidden" name="cmd" value="_s-xclick">
//! <input type="hidden" name="hosted_button_id" value="4ARJP4UBNMDW2">
//! <input type="image" src="https://www.paypalobjects.com/en_US/SE/i/btn/btn_donateCC_LG.gif" border="0" name="submit" alt="PayPal - The safer, easier way to pay online!">
//! <img alt="" border="0" src="https://www.paypalobjects.com/en_US/i/scr/pixel.gif" width="1" height="1">
//! </form>

extern crate num;
extern crate rand;
extern crate byteorder;

#[cfg(test)]
extern crate quickcheck;

use std::io::{Read, Write};

use std::net::TcpStream;

extern crate crypto;

/// SSH socket and transport details
pub mod transport {
  /// Reads and writes SSH messages
  pub mod ssh_socket;
  /// The SSH conversation
  ///
  /// The individual conversation bits go into this module.
  pub mod ssh_transport;
}

/// SSH I/O
mod sshio;
/// SSH-related messages, defined as types
pub mod packets;

fn main() {
  let mut tcp_socket = TcpStream::connect("127.0.0.1:9001").unwrap();

  let reader = &mut tcp_socket.try_clone().unwrap() as &mut Read;
  let writer = &mut tcp_socket as &mut Write;

  let mut socket = transport::ssh_socket::Socket::new(reader, writer);
  let mut transport = transport::ssh_transport::Transport::new(&mut socket);

  println!("Packet!: {:?}", transport.read());
}
