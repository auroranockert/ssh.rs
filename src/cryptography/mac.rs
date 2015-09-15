use crypto::mac;

pub struct None;

impl mac::Mac for None {
  fn input(&mut self, _: &[u8]) {
    return;
  }

  fn reset(&mut self) {
    return;
  }

  fn result(&mut self) -> mac::MacResult {
    return mac::MacResult::new(&[]);
  }

  fn raw_result(&mut self, _: &mut [u8]) {
    return;
  }

  fn output_bytes(&self) -> usize {
    return 0;
  }
}
