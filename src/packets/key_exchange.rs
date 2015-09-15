packet_use!();

use rand;
use rand::Rng;

#[derive(Clone, Debug, PartialEq)]
pub struct Cookie {
  pub cookie: [u8; 16]
}

impl Cookie {
  pub fn new() -> Cookie {
    return Cookie::from_rng(&mut rand::thread_rng());
  }

  pub fn from_rng(rng: &mut rand::Rng) -> Cookie {
    let mut cookie = [0u8; 16];

    rng.fill_bytes(&mut cookie);

    return Cookie { cookie: cookie };
  }
}

impl Default for Cookie {
  fn default() -> Cookie {
    return Cookie::new()
  }
}

impl FromSSH for Cookie {
  fn from_ssh(reader: &mut Read) -> byteorder::Result<Self> {
    let mut cookie = [0u8; 16];

    for i in 0 .. 16 {
      cookie[i] = try!(FromSSH::from_ssh(reader));
    }

    return Ok(Cookie {
      cookie: cookie
    });
  }
}

impl ToSSH for Cookie {
  fn to_ssh(&self, writer: &mut Write) -> byteorder::Result<()> {
    for i in 0 .. 16 {
      try!(self.cookie[i].to_ssh(writer));
    }

    return Ok(());
  }
}

#[cfg(test)]
impl Arbitrary for Cookie {
  fn arbitrary<G: Gen>(g: &mut G) -> Cookie {
    return Cookie::from_rng(g);
  }
}

packet!(KeyExchangeInit {
  cookie: Cookie,
  kex_algorithms: Vec<String>,
  server_host_key_algorithms: Vec<String>,
  encryption_algorithms_client_to_server: Vec<String>,
  encryption_algorithms_server_to_client: Vec<String>,
  mac_algorithms_client_to_server: Vec<String>,
  mac_algorithms_server_to_client: Vec<String>,
  compression_algorithms_client_to_server: Vec<String>,
  compression_algorithms_server_to_client: Vec<String>,
  languages_client_to_server: Vec<String>,
  languages_server_to_client: Vec<String>,
  first_kex_packet_follows: bool,
  reserved: u32
});

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NewKeys;

impl FromSSH for NewKeys {
  fn from_ssh(_: &mut Read) -> byteorder::Result<Self> {
    return Ok(NewKeys);
  }
}

impl ToSSH for NewKeys {
  fn to_ssh(&self, _: &mut Write) -> byteorder::Result<()> {
    return Ok(());
  }
}

impl Arbitrary for NewKeys {
  fn arbitrary<G: Gen>(_: &mut G) -> NewKeys {
    return NewKeys;
  }
}
