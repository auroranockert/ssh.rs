use crypto::aes;
use crypto::symmetriccipher::SynchronousStreamCipher;

trait Decrypter {
  fn decrypt(&mut self, i: &[u8], o: &mut [u8]);

  fn block_size(&self) -> usize;
}

struct None;

impl Decrypter for None {
  fn decrypt(&mut self, i: &[u8], o: &mut [u8]) {
    o.clone_from_slice(i);
  }

  fn block_size(&self) -> usize {
    return 8;
  }
}

struct Aes128Ctr {
  decryptor: Box<SynchronousStreamCipher>
}

impl Aes128Ctr {
  fn new(iv: Vec<u8>, key: Vec<u8>) -> Aes128Ctr {
    let decryptor = aes::ctr(aes::KeySize::KeySize128, &key[..], &iv[..]);

    return Aes128Ctr { decryptor: decryptor };
  }
}

impl Decrypter for Aes128Ctr {
  fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
    self.decryptor.process(input, output);
  }

  fn block_size(&self) -> usize {
    return 16;
  }
}
