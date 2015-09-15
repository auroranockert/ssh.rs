use crypto::aes;
use crypto::symmetriccipher::SynchronousStreamCipher;

trait Encrypter {
  fn encrypt(&mut self, i: &[u8], o: &mut [u8]);

  fn block_size(&self) -> usize;
}

struct None;

impl Encrypter for None {
  fn encrypt(&mut self, i: &[u8], o: &mut [u8]) {
    o.clone_from_slice(i);
  }

  fn block_size(&self) -> usize {
    return 8;
  }
}

struct Aes128Ctr {
  encryptor: Box<SynchronousStreamCipher>
}

impl Aes128Ctr {
  fn new(iv: Vec<u8>, key: Vec<u8>) -> Aes128Ctr {
    let encryptor = aes::ctr(aes::KeySize::KeySize128, &key[..], &iv[..]);

    return Aes128Ctr { encryptor: encryptor };
  }
}

impl Encrypter for Aes128Ctr {
  fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
    self.encryptor.process(input, output);
  }

  fn block_size(&self) -> usize {
    return 16;
  }
}
