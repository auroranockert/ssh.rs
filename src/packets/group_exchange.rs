use std::io::{Read, Write};

use num::bigint::BigInt;

use sshio::{SSHRead, SSHWrite};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Request {
  pub min: u32,
  pub n: u32,
  pub max: u32
}

impl Request {
  pub fn read(reader: &mut Read) -> Request {
    let mut reader = reader;

    return Request {
      min: reader.read_uint32(),
      n: reader.read_uint32(),
      max: reader.read_uint32()
    };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_uint32(self.min);
    writer.write_uint32(self.n);
    writer.write_uint32(self.max);
  }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Group {
  pub p: BigInt,
  pub g: BigInt
}

impl Group {
  pub fn read(reader: &mut Read) -> Group {
    let mut reader = reader;

    return Group {
      p: reader.read_mpint(),
      g: reader.read_mpint()
    };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_mpint(&self.p);
    writer.write_mpint(&self.g);
  }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Init {
  pub e: BigInt
}

impl Init {
  pub fn read(reader: &mut Read) -> Init {
    let mut reader = reader;

    return Init {
      e: reader.read_mpint()
    };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_mpint(&self.e);
  }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reply {
  pub host_key_and_certificates: Vec<u8>,
  pub f: BigInt,
  pub signature: Vec<u8>
}

impl Reply {
  pub fn read(reader: &mut Read) -> Reply {
    let mut reader = reader;

    return Reply {
      host_key_and_certificates: reader.read_binary_string(),
      f: reader.read_mpint(),
      signature: reader.read_binary_string()
    };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_binary_string(&self.host_key_and_certificates);
    writer.write_mpint(&self.f);
    writer.write_binary_string(&self.signature);
  }
}

#[cfg(test)]
impl Arbitrary for Request {
  fn arbitrary<G: Gen>(g: &mut G) -> Request {
    return Request {
      min: Arbitrary::arbitrary(g),
      n: Arbitrary::arbitrary(g),
      max: Arbitrary::arbitrary(g)
    };
  }
}

#[cfg(test)]
impl Arbitrary for Group {
  fn arbitrary<G: Gen>(g: &mut G) -> Group {
    return Group {
      p: g.gen_bigint(1024),
      g: g.gen_bigint(1024)
    };
  }
}

#[cfg(test)]
impl Arbitrary for Init {
  fn arbitrary<G: Gen>(g: &mut G) -> Init {
    return Init {
      e: g.gen_bigint(1024)
    };
  }
}

#[cfg(test)]
impl Arbitrary for Reply {
  fn arbitrary<G: Gen>(g: &mut G) -> Reply {
    return Reply {
      host_key_and_certificates: Arbitrary::arbitrary(g),
      f: g.gen_bigint(1024),
      signature: Arbitrary::arbitrary(g)
    };
  }
}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use super::{Request, Group, Init, Reply};

  macro_rules! test_roundtrip {
    ($a:ident, $b:expr) => {{
      let mut writer = Cursor::new(Vec::new());

      $b.write(&mut writer);

      let mut reader = Cursor::new(writer.into_inner());

      return $b == $a::read(&mut reader);
    }};
  }


  #[quickcheck]
  fn request_roundtrips(packet: Request) -> bool {
    test_roundtrip!(Request, packet);
  }

  #[quickcheck]
  fn group_roundtrips(packet: Group) -> bool {
    test_roundtrip!(Group, packet);
  }

  #[quickcheck]
  fn init_roundtrips(packet: Init) -> bool {
    test_roundtrip!(Init, packet);
  }

  #[quickcheck]
  fn reply_roundtrips(packet: Reply) -> bool {
    test_roundtrip!(Reply, packet);
  }
}
