use std::io;
use std::io::Write;

use crypto::mac;
use crypto::mac::Mac;

use crypto::hmac;

use crypto::sha1;

use crypto::aes;

use crypto::symmetriccipher::SynchronousStreamCipher;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use num::{Zero, One};
use num::bigint::{BigInt, BigUint, ToBigInt, RandBigInt};

use rand;
use rand::Rng;

use transport::ssh_socket;

use packets::SSHPacket;
use packets::group_exchange;
use packets::key_exchange;

use hash::{Hash, SHA256};

use sshio::{SSHRead, SSHWrite};

struct NoneMac;

impl Mac for NoneMac {
  fn input(&mut self, _: &[u8]) {
    return;
  }

  fn reset(&mut self) {
    return;
  }

  fn result(&mut self) -> mac::MacResult {
    return mac::MacResult::new(&[]);
  }

  fn raw_result(&mut self, _: &mut [u8]) {
    return;
  }

  fn output_bytes(&self) -> usize {
    return 0;
  }
}

trait Encrypter {
  fn encrypt(&mut self, i: &[u8], o: &mut [u8]);

  fn block_size(&self) -> usize;
}

struct NoneEncrypter;

impl Encrypter for NoneEncrypter {
  fn encrypt(&mut self, i: &[u8], o: &mut [u8]) {
    o.clone_from_slice(i);
  }

  fn block_size(&self) -> usize {
    return 8;
  }
}

struct Aes128CtrEncrypter {
  encryptor: Box<SynchronousStreamCipher>
}

impl Aes128CtrEncrypter {
  fn new(iv: Vec<u8>, key: Vec<u8>) -> Aes128CtrEncrypter {
    let encryptor = aes::ctr(aes::KeySize::KeySize128, &key[..], &iv[..]);

    return Aes128CtrEncrypter { encryptor: encryptor };
  }
}

impl Encrypter for Aes128CtrEncrypter {
  fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
    self.encryptor.process(input, output);
  }

  fn block_size(&self) -> usize {
    return 16;
  }
}

trait Decrypter {
  fn decrypt(&mut self, i: &[u8], o: &mut [u8]);

  fn block_size(&self) -> usize;
}

struct NoneDecrypter;

impl Decrypter for NoneDecrypter {
  fn decrypt(&mut self, i: &[u8], o: &mut [u8]) {
    o.clone_from_slice(i);
  }

  fn block_size(&self) -> usize {
    return 8;
  }
}

struct Aes128CtrDecrypter {
  decryptor: Box<SynchronousStreamCipher>
}

impl Aes128CtrDecrypter {
  fn new(iv: Vec<u8>, key: Vec<u8>) -> Aes128CtrDecrypter {
    let decryptor = aes::ctr(aes::KeySize::KeySize128, &key[..], &iv[..]);

    return Aes128CtrDecrypter { decryptor: decryptor };
  }
}

impl Decrypter for Aes128CtrDecrypter {
  fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
    self.decryptor.process(input, output);
  }

  fn block_size(&self) -> usize {
    return 16;
  }
}


pub struct Transport<'a> {
  socket: &'a mut ssh_socket::Socket<'a>,
  session_identifier: Option<Vec<u8>>,
  version_exchange: ssh_socket::VersionExchange,
  encrypter: Box<Encrypter>,
  decrypter: Box<Decrypter>,
  signer: Box<Mac>, signer_sequence_number: u32,
  verifier: Box<Mac>, verifier_sequence_number: u32
}

impl<'a> Transport<'a> {
  pub fn new(socket: &'a mut ssh_socket::Socket<'a>) -> Transport<'a> {
    let vex = socket.version_exchange();

    let mut transport = Transport {
      socket: socket,
      session_identifier: None,
      version_exchange: vex,
      encrypter: Box::new(NoneEncrypter),
      decrypter: Box::new(NoneDecrypter),
      signer: Box::new(NoneMac), signer_sequence_number: 0,
      verifier: Box::new(NoneMac), verifier_sequence_number: 0
    };

    let s_kex = match transport.read() {
      SSHPacket::KeyExchange(k) => k,
      pkt => panic!(format!("FIXME: Unhandled message during key exchange ({:?})", pkt))
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

    self.write(&SSHPacket::NewKeys(key_exchange::NewKeys));

    let _ = match self.read() {
      SSHPacket::NewKeys(k) => k,
      pkt => panic!(format!("FIXME: Unhandled message during key exchange ({:?})", pkt))
    };

    println!("iv: {:?}, key: {:?}", iv_c2s, enc_key_c2s);

    self.encrypter = Box::new(Aes128CtrEncrypter::new(iv_c2s, enc_key_c2s));
    self.decrypter = Box::new(Aes128CtrDecrypter::new(iv_s2c, enc_key_s2c));

    self.signer = Box::new(hmac::Hmac::new(sha1::Sha1::new(), &mac_key_c2s[..]));
    self.verifier = Box::new(hmac::Hmac::new(sha1::Sha1::new(), &mac_key_s2c[..]));
  }

  pub fn read(&mut self) -> SSHPacket {
    println!("Entering read");
    
    let (mut reader, packet_length) = {
      let mut writer = io::Cursor::new(Vec::new());
    
      let length_data = self.socket.read_n(self.decrypter.block_size() as u32);
      println!("Encrypted Length: {:?}", &length_data[0 .. 4]);

      let mut decrypted_length_data = length_data.clone();
      self.decrypter.decrypt(&length_data[..], &mut decrypted_length_data[..]);
      writer.write_all(&decrypted_length_data[..]).unwrap();

      let mut reader = io::Cursor::new(writer.into_inner());
      let length = reader.read_u32::<BigEndian>().unwrap();

      println!("Length: {:?}", length);

      let already_read = self.decrypter.block_size() as u32 - 4;

      let mut payload_writer = io::Cursor::new(Vec::new());
      payload_writer.write_all(&reader.read_n(already_read)[..]).unwrap();

      let encrypted_payload_data = self.socket.read_n(length - already_read);
      let mut decrypted_payload_data = encrypted_payload_data.clone();
      self.decrypter.decrypt(&encrypted_payload_data[..], &mut decrypted_payload_data[..]);
      payload_writer.write_all(&decrypted_payload_data[..]).unwrap();

      let mut reader = io::Cursor::new(payload_writer.into_inner());

      (reader, length)
    };

    let padding_length = reader.read_u8().unwrap() as u32;

    let payload = reader.read_n(packet_length - padding_length - 1);
    let padding = reader.read_n(padding_length);
    let mac = self.socket.read_n(self.verifier.output_bytes() as u32);
    
    let calculated_mac = {
      let mut verifier_writer = io::Cursor::new(Vec::new());

      verifier_writer.write_uint32(self.verifier_sequence_number);
      verifier_writer.write_uint32(packet_length);
      verifier_writer.write_u8(padding_length as u8).unwrap();
      verifier_writer.write_all(&payload[..]).unwrap();
      verifier_writer.write_all(&padding[..]).unwrap();

      let buffer = verifier_writer.into_inner();

      // println!("Seq: {:?}", self.verifier_sequence_number);
      // println!("Buffer: {:?}", buffer);

      self.verifier_sequence_number += 1;

      self.verifier.reset();
      self.verifier.input(&buffer[..]);
      self.verifier.result()
    };

    // assert_eq!(mac, calculated_mac.code());

    let mut packet_reader = io::Cursor::new(payload);

    return SSHPacket::read(&mut packet_reader);
  }

  pub fn write(&mut self, packet: &SSHPacket) {
    let payload = {
      let mut writer = io::Cursor::new(Vec::new());
      packet.write(&mut writer);
      writer.into_inner()
    };

    let datastream = {
      let mut writer = io::Cursor::new(Vec::new());

      let padding_length = self.encrypter.block_size() - (5 + payload.len()) % self.encrypter.block_size();
      let padding_length = if padding_length < 4 { padding_length + self.encrypter.block_size() } else { padding_length };

      writer.write_u32::<BigEndian>((payload.len() + padding_length + 1) as u32).unwrap();
      writer.write_u8(padding_length as u8).unwrap();

      let padding = vec![0u8; padding_length];

      writer.write_all(&payload[..]).unwrap();
      writer.write_all(&padding[..]).unwrap();

      writer.into_inner()
    };

    let mac = {
      let mut signer_writer = io::Cursor::new(Vec::new());

      signer_writer.write_uint32(self.signer_sequence_number);
      signer_writer.write_all(&datastream[..]).unwrap();

      self.signer_sequence_number += 1;

      self.signer.reset();
      self.signer.input(&signer_writer.into_inner()[..]);
      self.signer.result()
    };

    let mut encrypted_datastream = datastream.clone();
    self.encrypter.encrypt(&datastream[..], &mut encrypted_datastream[..]);

    let binary_packet = {
      let mut packet_writer = io::Cursor::new(Vec::new());

      packet_writer.write_all(&encrypted_datastream[..]).unwrap();
      packet_writer.write_all(mac.code()).unwrap();

      packet_writer.into_inner()
    };

    self.socket.write_all(&binary_packet[..]).unwrap();
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
