use std::io;
use std::io::{Read, Write};

use byteorder;

use crypto::mac::Mac;

use transport::ssh_socket;

use cryptography;
use cryptography::decrypter::Decrypter;
use cryptography::encrypter::Encrypter;

use io::{FromSSH, ToSSH};

use packets::SSHPacket;

pub struct WriteState {
  encrypter: Box<Encrypter>,
  mac: Box<Mac>,
  sequence_number: u32
}

pub struct ReadState {
  decrypter: Box<Decrypter>,
  mac: Box<Mac>,
  sequence_number: u32
}

pub struct Transport<'a> {
  socket: &'a mut ssh_socket::Socket<'a>,
  session_identifier: Option<Vec<u8>>,
  version_exchange: ssh_socket::VersionExchange,
  read_state: ReadState,
  write_state: WriteState
}

impl<'a> Transport<'a> {
  pub fn new(socket: &'a mut ssh_socket::Socket<'a>, server: bool) -> Transport<'a> {
    let vex = socket.version_exchange(server);

    return Transport {
      socket: socket,
      session_identifier: None,
      version_exchange: vex,
      read_state: ReadState {
        decrypter: Box::new(cryptography::decrypter::None),
        mac: Box::new(cryptography::mac::None),
        sequence_number: 0
      },
      write_state: WriteState {
        encrypter: Box::new(cryptography::encrypter::None),
        mac: Box::new(cryptography::mac::None),
        sequence_number: 0
      }
    };
  }

  pub fn read(&mut self) -> byteorder::Result<SSHPacket> {
    let block_size = self.read_state.decrypter.block_size();

    let (payload, _, _) = {
      let packet_length = try!(u32::from_ssh(&mut self.socket)) as usize;
      let padding_length = try!(u8::from_ssh(&mut self.socket)) as usize;
      let payload_length = packet_length - padding_length - 1;
      let mac_length = self.read_state.mac.output_bytes();

      let mut payload = Vec::with_capacity(payload_length);
      let mut padding = Vec::with_capacity(padding_length);
      let mut mac = Vec::with_capacity(mac_length);

      try!(self.socket.take(payload_length as u64).read_to_end(&mut payload));
      try!(self.socket.take(padding_length as u64).read_to_end(&mut padding));
      try!(self.socket.take(mac_length as u64).read_to_end(&mut mac));

      (payload, padding, mac)
    };

    self.read_state.sequence_number += 1;

    return SSHPacket::from_ssh(&mut io::Cursor::new(payload));
  }

  pub fn write(&mut self, packet: &SSHPacket) -> byteorder::Result<()> {
    let payload = {
      let mut writer = io::Cursor::new(Vec::new());
      packet.to_ssh(&mut writer);
      writer.into_inner()
    };

    let datastream = {
      let mut writer = io::Cursor::new(Vec::new());

      let block_size = self.write_state.encrypter.block_size();
      let padding_length = block_size - (5 + payload.len()) % block_size;
      let padding_length = if padding_length < 4 { padding_length + block_size } else { padding_length };

      try!(((payload.len() + padding_length + 1) as u32).to_ssh(&mut writer));
      try!((padding_length as u8).to_ssh(&mut writer));

      let padding = vec![0u8; padding_length];

      try!(writer.write_all(&payload[..]));
      try!(writer.write_all(&padding[..]));

      writer.into_inner()
    };

    let mac = {
      let mut signer_writer = io::Cursor::new(Vec::new());

      try!(self.write_state.sequence_number.to_ssh(&mut signer_writer));
      try!(signer_writer.write_all(&datastream[..]));

      self.write_state.sequence_number += 1;

      self.write_state.mac.reset();
      self.write_state.mac.input(&signer_writer.into_inner()[..]);
      self.write_state.mac.result()
    };

    let mut encrypted_datastream = datastream.clone();
    self.write_state.encrypter.encrypt(&datastream[..], &mut encrypted_datastream[..]);

    let binary_packet = {
      let mut packet_writer = io::Cursor::new(Vec::new());

      try!(packet_writer.write_all(&encrypted_datastream[..]));
      try!(packet_writer.write_all(mac.code()));

      packet_writer.into_inner()
    };

    try!(self.socket.write_all(&binary_packet[..]));

    return Ok(());
  }
}
