use std::io;

pub struct VersionExchange {
  pub server: String,
  pub client: String
}

pub struct Socket {
  reader: Box<io::Read>,
  writer: Box<io::Write>
}

static SSH_IDENTIFIER: &'static str = "SSH-2.0-ssh.rs_0.0.1";

impl Socket {
  pub fn new(reader: Box<io::Read>, writer: Box<io::Write>) -> Socket {
    return Socket { reader: reader, writer: writer };
  }

  pub fn version_exchange(&mut self, server: bool) -> VersionExchange {
    let mut identifier = SSH_IDENTIFIER.to_owned();

    identifier.push('\r');
    identifier.push('\n');

    assert_eq!(self.writer.write(identifier.as_bytes()).unwrap(), identifier.len());

    if server {
      return VersionExchange {
        client: self.read_version(),
        server: SSH_IDENTIFIER.to_owned()
      };
    } else {
      return VersionExchange {
        client: SSH_IDENTIFIER.to_owned(),
        server: self.read_server_version()
      };
    }
  }

  fn read_version(&mut self) -> String {
    let mut name = read_until(&mut *self.reader, '\n');

    assert_eq!(name.pop(), Some('\r'));
    assert_eq!(&name[0 .. 8], "SSH-2.0-");

    return name;
  }

  fn read_server_version(&mut self) -> String {
    let mut name = read_until(&mut *self.reader, '\n');

    if name.pop() != Some('\r') || &name[0 .. 4] != "SSH-" {
      return self.read_server_version();
    }

    assert_eq!(&name[4 .. 8], "2.0-");

    return name;
  }
}

impl io::Read for Socket {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    return self.reader.read(buf);
  }
}

impl io::Write for Socket {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    return self.writer.write(buf);
  }

  fn flush(&mut self) -> io::Result<()> {
    return self.writer.flush();
  }
}

fn read_until(stream: &mut io::Read, stop: char) -> String {
  let mut buffer = [0u8];
  let mut string = String::new();

  let mut c = None;
  while c != Some(stop) {
    if let Some(character) = c {
      string.push(character)
    }

    let r = stream.read(&mut buffer);

    c = match r {
      Ok(1) => Some(buffer[0] as char),
      _ => None
    };
  }

  return string;
}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use super::Socket;

  use super::SSH_IDENTIFIER;

  static SSH_IDENTIFIER_SERVER: &'static str = "SSH-2.0-OpenSSH_6.2";
  static OLD_IDENTIFIER_SERVER: &'static str = "SSH-1.0-OpenSSH_6.2";

  #[test]
  fn does_version_exchange() {
    let mut server_identifier = SSH_IDENTIFIER_SERVER.as_bytes().to_owned();

    server_identifier.push('\r' as u8);
    server_identifier.push('\n' as u8);

    let mut reader = Cursor::new(server_identifier);
    let mut writer = Cursor::new(Vec::new());
    
    let version_exchange = {
      let mut socket = Socket::new(box reader, box writer);

      socket.version_exchange(false)
    };

    let mut client_identifier = SSH_IDENTIFIER.as_bytes().to_owned();

    client_identifier.push('\r' as u8);
    client_identifier.push('\n' as u8);

    assert_eq!(writer.into_inner(), client_identifier);
    assert_eq!(version_exchange.client, SSH_IDENTIFIER);
    assert_eq!(version_exchange.server, SSH_IDENTIFIER_SERVER);
  }

  #[test]
  #[should_panic]
  fn fails_unless_version_is_2_0() {
    let mut server_identifier = OLD_IDENTIFIER_SERVER.as_bytes().to_owned();

    server_identifier.push('\r' as u8);
    server_identifier.push('\n' as u8);

    let mut reader = Cursor::new(server_identifier);
    let mut writer = Cursor::new(Vec::new());
    
    let mut socket = Socket::new(&mut reader, &mut writer);

    let _ = socket.version_exchange(false);
  }
}
