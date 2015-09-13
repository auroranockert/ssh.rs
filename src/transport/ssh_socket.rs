/// SSH Socket for big win

use std::io;

/// A Socket can make Version exchange, and this struct holds the result of
/// that.
pub struct VersionExchange {
  pub server: String,
  pub client: String
}

/// SSH Socket with a reader and writer.
pub struct Socket<'a> {
  /// Reader
  reader: &'a mut io::Read,
  /// Writer
  writer: &'a mut io::Write
}

static SSH_IDENTIFIER_CLIENT: &'static str = "SSH-2.0-ssh.rs_0.0.1";

/// Implementation of SSH Socket.
impl<'a> Socket<'a> {
  /// Constructs a new `Socket<'a>`, connecting given `reader` and `writer`
  /// to it.
  pub fn new(reader: &'a mut io::Read, writer: &'a mut io::Write) -> Socket<'a> {
    return Socket { reader: reader, writer: writer };
  }

  /// Performs Version exchange with the client, returning the result as a
  /// struct.
  pub fn version_exchange(&mut self) -> VersionExchange {
    let mut client_identifier = SSH_IDENTIFIER_CLIENT.to_owned();

    client_identifier.push('\r');
    client_identifier.push('\n');

    assert_eq!(self.writer.write(client_identifier.as_bytes()).unwrap(), client_identifier.len());

    let mut name = read_until(self.reader, '\n');
    assert_eq!(name.pop(), Some('\r'));

    assert_eq!(&name[0 .. 8], "SSH-2.0-");

    return VersionExchange {
      client: SSH_IDENTIFIER_CLIENT.to_owned(),
      server: name
    };
  }
}

impl<'a> io::Read for Socket<'a> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    return self.reader.read(buf);
  }
}

impl<'a> io::Write for Socket<'a> {
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

  use super::SSH_IDENTIFIER_CLIENT;

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
      let mut socket = Socket::new(&mut reader, &mut writer);

      socket.version_exchange()
    };

    let mut client_identifier = SSH_IDENTIFIER_CLIENT.as_bytes().to_owned();

    client_identifier.push('\r' as u8);
    client_identifier.push('\n' as u8);

    assert_eq!(writer.into_inner(), client_identifier);
    assert_eq!(version_exchange.client, SSH_IDENTIFIER_CLIENT);
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

    let _ = socket.version_exchange();
  }
}
