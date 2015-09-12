use std::io::{Read, Write};

use std::net::TcpStream;

fn ssh_protocol_read_string(stream: &mut TcpStream, n: u8) -> String {
  let mut buffer = [0u8];
  let mut string = String::new();

  for _ in 0 .. n {
    let r = stream.read(&mut buffer);

    match r {
      Ok(1) => {
        string.push(buffer[0] as char);
      },
      _ => ()
    }
  }

  return string;
}

fn ssh_protocol_read_until(stream: &mut TcpStream, stop: char) -> String {
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

static SSH_IDENTIFIER_CLIENT: &'static str = "SSH-2.0-ssh.rs_0.0.1";
static SSH_IDENTIFIER_SERVER: &'static str = "SSH-2.0-OpenSSH_6.2";

pub fn read(stream: &mut TcpStream) -> (String, String, &'static str, &'static str) {
  assert_eq!(ssh_protocol_read_string(stream, 4), "SSH-");
  let major = ssh_protocol_read_string(stream, 1);
  assert_eq!(ssh_protocol_read_string(stream, 1), ".");
  let minor = ssh_protocol_read_string(stream, 1);
  assert_eq!(ssh_protocol_read_string(stream, 1), "-");
  let mut name = ssh_protocol_read_until(stream, '\n');
  assert_eq!(name.pop(), Some('\r'));

  assert_eq!(name, "OpenSSH_6.2");

  return (major, minor, SSH_IDENTIFIER_CLIENT, SSH_IDENTIFIER_SERVER);
}

pub fn write(stream: &mut TcpStream) {
  assert_eq!(stream.write(SSH_IDENTIFIER_CLIENT.as_bytes()).unwrap(), SSH_IDENTIFIER_CLIENT.len());
  assert_eq!(stream.write(b"\r\n").unwrap(), 2);
}
