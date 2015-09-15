use std::io;

use std::net::TcpStream;

use transport::ssh_socket::Socket;
use transport::ssh_transport::Transport;

pub struct Session {
  transport: Option<Transport>
}

impl Session {
  pub fn new() -> Session {
    return Session {
      transport: None
    };
  }

  pub fn connect(&mut self, host: &str) -> io::Result<()> {
    let tcp_socket = try!(TcpStream::connect(host));

    let reader = Box::new(tcp_socket.try_clone().unwrap());
    let writer = Box::new(tcp_socket);

    let socket = Socket::new(reader, writer);
    let transport = Transport::new(socket, false);

    self.transport = Some(transport);

    return Ok(());
  }
}
