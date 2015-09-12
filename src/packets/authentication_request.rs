use std::io::{Read, Write};

use sshio::{SSHRead, SSHWrite};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

#[derive(Clone, Debug, PartialEq)]
pub enum AuthenticationRequestMethodName {
  PublicKey,
  Password,
  Hostbased,
  NoneMethod
}

impl AuthenticationRequestMethodName {
  pub fn from_str(name: &str) -> AuthenticationRequestMethodName {
    return match name {
      "publickey" => AuthenticationRequestMethodName::PublicKey,
      "password" => AuthenticationRequestMethodName::Password,
      "hostbased" => AuthenticationRequestMethodName::Hostbased,
      "none" => AuthenticationRequestMethodName::NoneMethod,
      _ => panic!("Unknown method name.")
    }
  }

  pub fn to_string(&self) -> &'static str {
    return match self {
      &AuthenticationRequestMethodName::PublicKey => "publickey",
      &AuthenticationRequestMethodName::Password => "password",
      &AuthenticationRequestMethodName::Hostbased => "hostbased",
      &AuthenticationRequestMethodName::NoneMethod => "none"
    }
  }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticationRequest {
  pub user_name: String,
  pub service_name: String,
  pub method_name: AuthenticationRequestMethodName
}

impl AuthenticationRequest {
  pub fn read(reader: &mut Read) -> AuthenticationRequest {
    let mut reader = reader;

    let user_name = reader.read_string();
    let service_name = reader.read_string();
    let method_name = reader.read_string();

    return AuthenticationRequest {
      user_name: user_name,
      service_name: service_name,
      method_name: AuthenticationRequestMethodName::from_str(method_name.as_str())
    };
  }

  pub fn write(&self, writer: &mut Write) {
    let mut writer = writer;

    writer.write_string(self.user_name.as_str());
    writer.write_string(self.service_name.as_str());
    writer.write_string(self.method_name.to_string());
  }
}

#[cfg(test)]
impl Arbitrary for AuthenticationRequestMethodName {
  fn arbitrary<G: Gen>(g: &mut G) -> AuthenticationRequestMethodName {
    let i = g.gen::<usize>() % 4;
    let s = ["publickey", "password", "hostbased", "none"][i];
    return AuthenticationRequestMethodName::from_str(s);
  }
}


#[cfg(test)]
impl Arbitrary for AuthenticationRequest {
  fn arbitrary<G: Gen>(g: &mut G) -> AuthenticationRequest {
    return AuthenticationRequest {
      user_name: Arbitrary::arbitrary(g),
      service_name: Arbitrary::arbitrary(g),
      method_name: Arbitrary::arbitrary(g)
    };
  }
}

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use super::AuthenticationRequest;

  #[quickcheck]
  fn roundtrips(packet: AuthenticationRequest) -> bool {
    let mut writer = Cursor::new(Vec::new());

    packet.write(&mut writer);

    let mut reader = Cursor::new(writer.into_inner());

    return packet == AuthenticationRequest::read(&mut reader);
  }
}
