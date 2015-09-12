use std::io::{Read, Write};

use sshio::{SSHRead, SSHWrite};

#[derive(Clone, Debug, Default)]
pub struct KeyExchangeInit {
  pub cookie: [u8; 16],
  pub kex_algorithms: Vec<String>,
  pub server_host_key_algorithms: Vec<String>,
  pub encryption_algorithms_client_to_server: Vec<String>,
  pub encryption_algorithms_server_to_client: Vec<String>,
  pub mac_algorithms_client_to_server: Vec<String>,
  pub mac_algorithms_server_to_client: Vec<String>,
  pub compression_algorithms_client_to_server: Vec<String>,
  pub compression_algorithms_server_to_client: Vec<String>,
  pub languages_client_to_server: Vec<String>,
  pub languages_server_to_client: Vec<String>,
  pub first_kex_packet_follows: bool,
  pub reserved: u32
}

impl KeyExchangeInit {
  pub fn read(reader: &mut Read) -> KeyExchangeInit {
    let mut reader = reader;

    let mut cookie = [0u8; 16];
    reader.read_n_into_buffer(&mut cookie);

    let kex_algorithms = reader.read_name_list();
    let server_host_key_algorithms = reader.read_name_list();
    let encryption_algorithms_client_to_server = reader.read_name_list();
    let encryption_algorithms_server_to_client = reader.read_name_list();
    let mac_algorithms_client_to_server = reader.read_name_list();
    let mac_algorithms_server_to_client = reader.read_name_list();
    let compression_algorithms_client_to_server = reader.read_name_list();
    let compression_algorithms_server_to_client = reader.read_name_list();
    let languages_client_to_server = reader.read_name_list();
    let languages_server_to_client = reader.read_name_list();

    let first_kex_packet_follows = reader.read_bool();
    let reserved = reader.read_uint32();

    return KeyExchangeInit {
      cookie: cookie,
      kex_algorithms: kex_algorithms,
      server_host_key_algorithms: server_host_key_algorithms,
      encryption_algorithms_client_to_server: encryption_algorithms_client_to_server,
      encryption_algorithms_server_to_client: encryption_algorithms_server_to_client,
      mac_algorithms_client_to_server: mac_algorithms_client_to_server,
      mac_algorithms_server_to_client: mac_algorithms_server_to_client,
      compression_algorithms_client_to_server: compression_algorithms_client_to_server,
      compression_algorithms_server_to_client: compression_algorithms_server_to_client,
      languages_client_to_server: languages_client_to_server,
      languages_server_to_client: languages_server_to_client,
      first_kex_packet_follows: first_kex_packet_follows,
      reserved: reserved
    };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_all(&self.cookie).unwrap();
    writer.write_name_list(&self.kex_algorithms);
    writer.write_name_list(&self.server_host_key_algorithms);
    writer.write_name_list(&self.encryption_algorithms_client_to_server);
    writer.write_name_list(&self.encryption_algorithms_server_to_client);
    writer.write_name_list(&self.mac_algorithms_client_to_server);
    writer.write_name_list(&self.mac_algorithms_server_to_client);
    writer.write_name_list(&self.compression_algorithms_client_to_server);
    writer.write_name_list(&self.compression_algorithms_server_to_client);
    writer.write_name_list(&self.languages_client_to_server);
    writer.write_name_list(&self.languages_server_to_client);
    writer.write_bool(self.first_kex_packet_follows);
    writer.write_uint32(self.reserved);
  }
}

#[derive(Clone, Debug, Default)]
pub struct NewKeys;

impl NewKeys {
  pub fn read(_: &mut Read) -> NewKeys {
    return NewKeys;
  }

  pub fn write(&self, _: &mut Write) {
  }
}
