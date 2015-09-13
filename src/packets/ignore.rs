use std::io::{Read, Write};

use sshio::{SSHRead, SSHWrite};

#[derive(Clone, Debug, Default)]
pub struct Ignore {
  data: String
}

impl Ignore {
  pub fn read(reader: &mut Read) -> Ignore {
    let mut reader = reader;

    return Ignore { data: reader.read_string() };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_string(&self.data[..]);
  }
}
