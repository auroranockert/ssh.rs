use std::io::{Read, Write};

use sshio::{SSHRead, SSHWrite};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Disconnect {
  pub reason: u32,
  pub message: String,
  pub language: String
}

impl Disconnect {
  pub fn read(reader: &mut Read) -> Disconnect {
    let mut reader = reader;

    let reason = reader.read_uint32();

    let message = reader.read_string();
    let language = reader.read_string();

    return Disconnect { reason: reason, message: message, language: language };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_uint32(self.reason);
    writer.write_string(self.message.as_str());
    writer.write_string(self.language.as_str());
  }
}

#[cfg(test)]
impl Arbitrary for Disconnect {
  fn arbitrary<G: Gen>(g: &mut G) -> Disconnect {
    return Disconnect {
      reason: Arbitrary::arbitrary(g),
      message: Arbitrary::arbitrary(g),
      language: Arbitrary::arbitrary(g)
    };
  }
}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use super::Disconnect;

  #[quickcheck]
  fn roundtrips(packet: Disconnect) -> bool {
    let mut writer = Cursor::new(Vec::new());

    packet.write(&mut writer);

    let mut reader = Cursor::new(writer.into_inner());

    return packet == Disconnect::read(&mut reader);
  }
}
