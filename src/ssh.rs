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

pub mod session;

fn main() {
  let mut session = session::Session::new();
  
  session.connect("127.0.0.1:22").unwrap();

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

  // println!("Packet!: {:?}", transport.read().unwrap());
}
