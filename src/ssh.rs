#![feature(libc)]
#![feature(convert)]

#![cfg_attr(test, feature(plugin))]
#![cfg_attr(test, plugin(quickcheck_macros))]

extern crate num;
extern crate rand;
extern crate byteorder;
extern crate gmp;

#[cfg(test)]
extern crate quickcheck;

use std::io::{Cursor, Write};
use std::net::TcpStream;

use num::{Zero, One};
use num::bigint::{BigInt, BigUint, ToBigInt, RandBigInt};

pub mod hash;
mod sshio;
mod protocol_negotiation;
mod packets {
  pub mod group_exchange;
  pub mod disconnect;
  pub mod key_exchange;
}

use sshio::{SSHRead, SSHWrite};

use packets::disconnect;
use packets::group_exchange;
use packets::key_exchange;

use rand::Rng;

use hash::{Hash, SHA256};

use gmp::rand::RandState;
use gmp::mpz::Mpz;

// fn main() {
//   ssh_connect("127.0.0.1:22");
// }

// fn ssh_connect(to: &str) {
//   let mut socket = TcpStream::connect(to).unwrap();

//   let (major, minor, v_c, v_s) = protocol_negotiation::read(&mut socket);

//   println!("Using version: SSH-{}.{}", major, minor);

//   assert_eq!(major, "2");
//   assert_eq!(minor, "0");

//   protocol_negotiation::write(&mut socket);

//   let kex_s = match socket.read_packet() {
//     SSHPacket::KeyExchange(kex) => kex,
//     _ => panic!("Unexpected packet")
//   };

//   let mut cookie = [0u8; 16];

//   let mut rng = rand::thread_rng();
//   for x in cookie.iter_mut() {
//       *x = rng.gen::<u8>()
//   }

//   let enc = vec![
//     "aes128-cbc".to_string(),
//   ];

//   let mac = vec![
//     "hmac-sha1".to_string()
//   ];

//   let comp = vec![
//     "none".to_string()
//   ];

//   let kex_c = key_exchange::KeyExchangeInit {
//     cookie: cookie,
//     first_kex_packet_follows: true,
//     kex_algorithms: vec![
//       "diffie-hellman-group-exchange-sha256".to_string()
//     ],
//     server_host_key_algorithms: vec![
//       "ssh-rsa".to_string(),
//     ],
//     encryption_algorithms_client_to_server: enc.clone(),
//     encryption_algorithms_server_to_client: enc.clone(),
//     mac_algorithms_client_to_server: mac.clone(),
//     mac_algorithms_server_to_client: mac.clone(),
//     compression_algorithms_client_to_server: comp.clone(),
//     compression_algorithms_server_to_client: comp.clone(),
//     ..Default::default()
//   };

//   socket.write_packet(&SSHPacket::KeyExchange(kex_c.clone()));

//   let gex = group_exchange::Request { min: 1024, n: 1024, max: 8192 };

//   socket.write_packet(&SSHPacket::GroupExchangeRequest(gex));

//   let geg = match socket.read_packet() {
//     SSHPacket::GroupExchangeGroup(g) => g,
//     _ => panic!("Unexpected packet")
//   };

//   let p = geg.p;
//   let g = geg.g;

//   let x = gen_mpz_between((p - 1) / 2); // Under construction.
//   let e = mod_exp(&g, &x, &p);

//   let gei = group_exchange::Init { e: e.clone() };

//   socket.write_packet(&SSHPacket::GroupExchangeInit(gei));

//   let ger = match socket.read_packet() {
//     SSHPacket::GroupExchangeReply(g) => g,
//     _ => panic!("Unexpected packet")
//   };

//   let mut writer = Cursor::new(Vec::new());

//   writer.write_all(v_c.as_bytes()).unwrap();
//   writer.write_all(v_s.as_bytes()).unwrap();

//   kex_c.write(&mut writer);
//   kex_s.write(&mut writer);

//   writer.write_all(&ger.host_key_and_certificates[..]).unwrap();
//   writer.write_mpint(&e);
//   writer.write_mpint(&ger.f);
//   writer.write_mpint(&mod_exp(&ger.f, &x, &p));

//   let mut hash = SHA256::new();

//   hash.update(&writer.into_inner()[..]);

//   let h = hash.digest();

//   println!("Session ID: {:?}", h);

//   println!("Packet: {:?}", socket.read_packet());

//   socket.write_packet(&SSHPacket::NewKeys(key_exchange::NewKeys));
// }

// // Return a randomly-selected integer useful with GMP
// pub fn gen_mpz_between(lower: &Mpz, upper: &Mpz) -> Mpz {
//   let new_upper = upper - lower;

//   return RandState::new().urandom(&new_upper) + lower;
// }

// #[cfg(test)]
// mod tests {
//   use gmp::mpz::Mpz;
//   use super::gen_mpz_between;
//   #[quickcheck]
//   fn mpz_is_between(lbound: Mpz, ubound: Mpz) -> bool {
//     if &lbound >= &ubound { return true }

//     let a = gen_mpz_between(&lbound, &ubound);
//     return &a < &ubound && &a >= &lbound;
//   }
// }

// pub fn mod_exp(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
//   let mut result: BigUint = One::one();
//   let mut base = base.to_biguint().unwrap();
//   let mut exponent = exponent.to_biguint().unwrap();
//   let modulus = modulus.to_biguint().unwrap();

//   while exponent > Zero::zero() {
//     let one: BigUint = One::one();
//     // Accumulate current base if current exponent bit is 1
//     if (&exponent & one) == One::one() {
//       result = result * &base;
//       result = result % &modulus;
//     }
//     // Get next base by squaring
//     base = &base * &base;
//     base = &base % &modulus;

//     // Get next bit of exponent
//     exponent = &exponent >> 1;
//   }

//   return result.to_bigint().unwrap();
// }

#[derive(Debug)]
enum SSHPacket {
  Disconnect(disconnect::Disconnect),
  KeyExchange(key_exchange::KeyExchangeInit),
  NewKeys(key_exchange::NewKeys),
  GroupExchangeRequest(group_exchange::Request),
  GroupExchangeGroup(group_exchange::Group),
  GroupExchangeInit(group_exchange::Init),
  GroupExchangeReply(group_exchange::Reply)
}
