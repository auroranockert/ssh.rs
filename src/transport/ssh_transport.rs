use std::io;
use std::io::Write;

use transport::ssh_socket;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use num::{Zero, One};
use num::bigint::{BigInt, BigUint, ToBigInt, RandBigInt};

use rand;
use rand::Rng;

use packets::SSHPacket;
use packets::group_exchange;
use packets::key_exchange;
use packets::authentication_request;

use hash::{Hash, SHA256};

use sshio::{SSHRead, SSHWrite};

/// Holds socket, session identifier and version-exchange information.
pub struct Transport<'a> {
  socket: &'a mut ssh_socket::Socket<'a>,
  session_identifier: Option<Vec<u8>>,
  version_exchange: ssh_socket::VersionExchange
}

impl<'a> Transport<'a> {
  pub fn new(socket: &'a mut ssh_socket::Socket<'a>) -> Transport<'a> {
    let vex = socket.version_exchange();

    let mut transport = Transport {
      socket: socket,
      session_identifier: None,
      version_exchange: vex
    };

    let s_kex = match transport.read() {
      SSHPacket::KeyExchange(k) => k,
      _ => panic!("FIXME: Unhandled message during key exchange")
    };
    let c_kex = transport.start_rekey();

    transport.rekey(&c_kex, &s_kex);

    return transport;
  }

  pub fn start_rekey(&mut self) -> key_exchange::KeyExchangeInit {
    let mut rng = rand::thread_rng();
    let mut cookie = [0u8; 16];
    for x in cookie.iter_mut() { *x = rng.gen::<u8>() }

    let enc = vec![
      "aes128-ctr".to_string(),
    ];

    let mac = vec![
      "hmac-sha1".to_string()
    ];

    let comp = vec![
      "none".to_string()
    ];

    let kex = key_exchange::KeyExchangeInit {
      cookie: cookie,
      first_kex_packet_follows: true,
      kex_algorithms: vec!["diffie-hellman-group-exchange-sha256".to_string()],
      server_host_key_algorithms: vec!["ssh-rsa".to_string()],
      encryption_algorithms_client_to_server: enc.clone(),
      encryption_algorithms_server_to_client: enc.clone(),
      mac_algorithms_client_to_server: mac.clone(),
      mac_algorithms_server_to_client: mac.clone(),
      compression_algorithms_client_to_server: comp.clone(),
      compression_algorithms_server_to_client: comp.clone(),
      ..Default::default()
    };

    self.write(&SSHPacket::KeyExchange(kex.clone()));

    return kex;
  }

  pub fn rekey(&mut self, kex_c: &key_exchange::KeyExchangeInit, kex_s: &key_exchange::KeyExchangeInit) {
    // TODO: Support other methods than Group Exchange Diffie-Hellman
    // TODO: Check if Group Exchange is supported by the other side

    let gex = group_exchange::Request { min: 1024, n: 1024, max: 8192 };

    self.write(&SSHPacket::GroupExchangeRequest(gex.clone()));

    let geg = match self.read() {
      SSHPacket::GroupExchangeGroup(g) => g,
      p => {
        println!("{:?}", p);
        panic!("Unexpected packet!")
      }
    };

    let mut rng = rand::thread_rng();

    let p = geg.p;
    let x = rng.gen_bigint_range(&2.to_bigint().unwrap(), &((&p - &1.to_bigint().unwrap()) / &2.to_bigint().unwrap()));
    let e = mod_exp(&geg.g, &x, &p);

    let gei = group_exchange::Init { e: e.clone() };

    self.write(&SSHPacket::GroupExchangeInit(gei));

    let ger = match self.read() {
      SSHPacket::GroupExchangeReply(g) => g,
      _ => panic!("Unexpected packet!")
    };

    let k = mod_exp(&ger.f, &x, &p);

    println!("Shared key: {:?}", k);

    let mut writer = io::Cursor::new(Vec::new());

    writer.write_string(&self.version_exchange.client);
    writer.write_string(&self.version_exchange.server);

    let mut w = io::Cursor::new(Vec::new());
    SSHPacket::KeyExchange(kex_c.clone()).write(&mut w);
    writer.write_binary_string(&w.into_inner()[..]);

    let mut w = io::Cursor::new(Vec::new());
    SSHPacket::KeyExchange(kex_s.clone()).write(&mut w);
    writer.write_binary_string(&w.into_inner()[..]);

    writer.write_binary_string(&ger.host_key_and_certificates);
    writer.write_uint32(gex.min);
    writer.write_uint32(gex.n);
    writer.write_uint32(gex.max);
    writer.write_mpint(&p);
    writer.write_mpint(&geg.g);
    writer.write_mpint(&e);
    writer.write_mpint(&ger.f);
    writer.write_mpint(&k);

    let buffer = writer.into_inner();

    println!("Buffer: {:?}", buffer);

    let mut hash = SHA256::new();

    hash.update(&buffer[..]);

    let h = hash.digest();

    let session_identifier = match &self.session_identifier {
      &None => h.clone(),
      &Some(ref s) => s.clone()
    };

    self.session_identifier = Some(session_identifier.clone());

    let iv_c2s = generate_key(&mut SHA256::new(), &k, &h[..], b"A", &session_identifier[..]);
    let iv_s2c = generate_key(&mut SHA256::new(), &k, &h[..], b"B", &session_identifier[..]);

    let enc_key_c2s = generate_key(&mut SHA256::new(), &k, &h[..], b"C", &session_identifier[..]);
    let enc_key_s2c = generate_key(&mut SHA256::new(), &k, &h[..], b"D", &session_identifier[..]);

    let mac_key_c2s = generate_key(&mut SHA256::new(), &k, &h[..], b"E", &session_identifier[..]);
    let mac_key_s2c = generate_key(&mut SHA256::new(), &k, &h[..], b"F", &session_identifier[..]);

    println!("Session ID: {:?}", h);
    println!("IV (c2s): {:?}", iv_c2s);
    println!("IV (s2c): {:?}", iv_s2c);
    println!("Key (c2s): {:?}", enc_key_c2s);
    println!("Key (s2c): {:?}", enc_key_s2c);
    println!("MAC (c2s): {:?}", mac_key_c2s);
    println!("MAC (s2c): {:?}", mac_key_s2c);

    self.write(&SSHPacket::NewKeys(key_exchange::NewKeys));

    panic!("Oh noes, sowwy, not implemented :C")
  }

  /// Reads bytes from the transport socket and returns an `SSHPacket`.
  pub fn read(&mut self) -> SSHPacket {
    let packet_length = self.socket.read_u32::<BigEndian>().unwrap();
    let padding_length = self.socket.read_u8().unwrap() as u32;

    let payload = self.socket.read_n(packet_length - padding_length - 1);
    let padding = self.socket.read_n(padding_length);
    // let mac = self.read_n(mac_length);

    // TODO: Check padding, mac

    let mut reader = io::Cursor::new(payload);

    return SSHPacket::read(&mut reader);
  }

  /// Understands and writes `SSHPacket` onto the transport socket.
  ///
  /// Messages are padded, and that's taken into account.
  pub fn write(&mut self, packet: &SSHPacket) {
    let mut writer = io::Cursor::new(Vec::new());

    packet.write(&mut writer);

    let payload = writer.into_inner();

    let padding_length = 8 - (5 + payload.len()) % 8;
    let padding_length = if padding_length < 4 { padding_length + 8 } else { padding_length };

    self.socket.write_u32::<BigEndian>((payload.len() + padding_length + 1) as u32).unwrap();
    self.socket.write_u8(padding_length as u8).unwrap();

    let padding = vec![0u8; padding_length];

    self.socket.write_all(&payload[..]).unwrap();
    self.socket.write_all(&padding[..]).unwrap();
    // TODO: Calculate the MAC
  }
}

fn generate_key(hsh: &mut Hash, k: &BigInt, h: &[u8], c: &[u8], sid: &[u8]) -> Vec<u8> {
  let mut w = io::Cursor::new(Vec::new());
  w.write_mpint(k);

  hsh.update(&w.into_inner()[..]);
  hsh.update(h);
  hsh.update(c);
  hsh.update(sid);

  return hsh.digest();
}

fn mod_exp(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
  let mut result: BigUint = One::one();
  let mut base = base.to_biguint().unwrap();
  let mut exponent = exponent.to_biguint().unwrap();
  let modulus = modulus.to_biguint().unwrap();

  while exponent > Zero::zero() {
    let one: BigUint = One::one();
    // Accumulate current base if current exponent bit is 1
    if (&exponent & one) == One::one() {
      result = result * &base;
      result = result % &modulus;
    }
    // Get next base by squaring
    base = &base * &base;
    base = &base % &modulus;

    // Get next bit of exponent
    exponent = &exponent >> 1;
  }

  return result.to_bigint().unwrap();
}
