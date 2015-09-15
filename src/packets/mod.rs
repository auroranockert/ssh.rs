use std::io::{Read, Write};

use byteorder;

use io::{FromSSH, ToSSH};

macro_rules! packet_use {
  () => {
    use std::io::{Read, Write};

    use byteorder;

    #[cfg(test)]
    use quickcheck::{Arbitrary, Gen};

    use io::{FromSSH, ToSSH};
  }
}

macro_rules! packet {
  ( $struct_name:ident { $( $name:ident: $ty:ty ),* }) => {
    #[derive(Clone, Debug, Default, PartialEq)]
    pub struct $struct_name {
      $(pub $name: $ty,)*
    }

    impl FromSSH for $struct_name {
      fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
        return Ok($struct_name {
          $($name: try!(FromSSH::from_ssh(reader)),)*
        });
      }
    }

    impl ToSSH for $struct_name {
      fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
        $(try!(self.$name.to_ssh(writer));)*

        return Ok(());
      }
    }

    #[cfg(test)]
    impl Arbitrary for $struct_name {
      fn arbitrary<G: Gen>(g: &mut G) -> $struct_name {
        return $struct_name {
          $($name: Arbitrary::arbitrary(g),)*
        };
      }
    }
  };
}

pub mod disconnect;
// pub mod group_exchange;
pub mod ignore;
pub mod key_exchange;
// pub mod authentication_request;

#[derive(Debug)]
pub enum SSHPacket {
  Disconnect(disconnect::Disconnect),
  Ignore(ignore::Ignore),
  KeyExchange(key_exchange::KeyExchangeInit),
  NewKeys(key_exchange::NewKeys)
  // GroupExchangeRequest(group_exchange::Request),
  // GroupExchangeGroup(group_exchange::Group),
  // GroupExchangeInit(group_exchange::Init),
  // GroupExchangeReply(group_exchange::Reply),
  // AuthenticationRequest(authentication_request::AuthenticationRequest)
}

macro_rules! r {
  ($a:path, $b:ty, $r:ident) => {
    {
      let result: byteorder::Result<$b> = FromSSH::from_ssh($r);

      $a(try!(result))
    }
  }
}

impl FromSSH for SSHPacket {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    return Ok(match try!(u8::from_ssh(reader)) {
      1 =>  r!(SSHPacket::Disconnect, disconnect::Disconnect, reader),
      2 =>  r!(SSHPacket::Ignore, ignore::Ignore, reader),
      20 => r!(SSHPacket::KeyExchange, key_exchange::KeyExchangeInit, reader),
      21 => r!(SSHPacket::NewKeys, key_exchange::NewKeys, reader),
      // 31 => SSHPacket::GroupExchangeGroup(group_exchange::Group::read(reader)),
      // 32 => SSHPacket::GroupExchangeInit(group_exchange::Init::read(reader)),
      // 33 => SSHPacket::GroupExchangeReply(group_exchange::Reply::read(reader)),
      // 34 => SSHPacket::GroupExchangeRequest(group_exchange::Request::read(reader)),
      // 50 => SSHPacket::AuthenticationRequest(authentication_request::AuthenticationRequest::read(reader)),
      t => panic!(format!("Oh noes, unknown packet type {:?}", t))
    });
  }
}

macro_rules! w {
  ($n:expr, $p:ident, $w:ident) => {
    {
      try!(($n as u8).to_ssh($w));
      try!($p.to_ssh($w));
    }
  }
}

impl ToSSH for SSHPacket {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    return Ok(match self {
      &SSHPacket::Disconnect(ref p) => w!(1, p, writer),
      &SSHPacket::Ignore(ref p) => w!(2, p, writer),
      &SSHPacket::KeyExchange(ref p) => w!(20, p, writer),
      &SSHPacket::NewKeys(ref p) => w!(21, p, writer)
      // 31 => SSHPacket::GroupExchangeGroup(group_exchange::Group::read(reader)),
      // 32 => SSHPacket::GroupExchangeInit(group_exchange::Init::read(reader)),
      // 33 => SSHPacket::GroupExchangeReply(group_exchange::Reply::read(reader)),
      // 34 => SSHPacket::GroupExchangeRequest(group_exchange::Request::read(reader)),
      // 50 => SSHPacket::AuthenticationRequest(authentication_request::AuthenticationRequest::read(reader)),
    });
  }
}

#[cfg(test)]
mod test {
  use std::io::Cursor;

  use io::{FromSSH, ToSSH};

  use super::disconnect;
  use super::ignore;
  use super::key_exchange;

  macro_rules! quickcheck_roundtrip {
    ($ty:ty, $name:ident) => {
      #[quickcheck]
      fn $name(value: $ty) -> bool {
        let v0 = {
          let mut writer = Cursor::new(Vec::new());
          value.to_ssh(&mut writer).unwrap();
          writer.into_inner()
        };

        let v1: $ty = {
          let length = v0.len() as u64;
          let mut reader = Cursor::new(v0);
          let result = FromSSH::from_ssh(&mut reader);

          if reader.position() != length {
            return false;
          }

          result.unwrap()
        };

        return v1 == value;
      }
    };
  }

  quickcheck_roundtrip!(ignore::Ignore, quickcheck_roundtrip_ignore);
  quickcheck_roundtrip!(disconnect::Disconnect, quickcheck_roundtrip_disconnect);
  // quickcheck_roundtrip!(key_exchange::KeyExchangeInit, quickcheck_roundtrip_kex); // TODO: Create list struct
  quickcheck_roundtrip!(key_exchange::NewKeys, quickcheck_roundtrip_new_keys);
}