mod read;
mod write;

pub use self::read::FromSSH;
pub use self::write::ToSSH;

#[cfg(test)]
mod tests {
  use std::io::Cursor;

  use gmp::mpz::Mpz;

  use super::{FromSSH, ToSSH};

  macro_rules! quickcheck_roundtrip {
    ($ty:ty, $name:ident) => {
      #[quickcheck]
      fn $name(value: $ty) -> bool {
        let v0 = {
          let mut writer = Cursor::new(Vec::new());
          value.to_ssh(&mut writer).unwrap();
          writer.into_inner()
        };

        let v1: $ty = {
          let length = v0.len() as u64;
          let mut reader = Cursor::new(v0);
          let result = FromSSH::from_ssh(&mut reader);

          if reader.position() != length {
            return false;
          }

          result.unwrap()
        };

        return v1 == value;
      }
    };
  }

  macro_rules! test_roundtrip {
    ($ty:ident, $name:ident, $a:expr, $b:expr) => {
      #[test]
      fn $name () {
        let a: $ty = From::from($a);
        let b = $b;

        let v0 = {
          let mut writer = Cursor::new(Vec::new());
          a.to_ssh(&mut writer).unwrap();
          writer.into_inner()
        };

        assert_eq!(v0, b);

        let v1: $ty = {
          let mut reader = Cursor::new(v0);
          let result = FromSSH::from_ssh(&mut reader);
          assert_eq!(reader.position(), b.len() as u64);
          result.unwrap()
        };

        assert_eq!(v1, a);
      }
    };
  }

  quickcheck_roundtrip!(u8, quickcheck_roundtrip_u8);

  test_roundtrip!(u8, test_u8_0, 0u8, vec![0]);

  quickcheck_roundtrip!(bool, quickcheck_roundtrip_bool);

  test_roundtrip!(bool, test_bool_true, true, vec![1]);
  test_roundtrip!(bool, test_bool_false, false, vec![0]);

  quickcheck_roundtrip!(u32, quickcheck_roundtrip_u32);

  test_roundtrip!(u32, test_u32_0, 0u32, vec![0, 0, 0, 0]);

  quickcheck_roundtrip!(Vec<u8>, quickcheck_roundtrip_binary_string);
  quickcheck_roundtrip!(String, quickcheck_roundtrip_string);

  // quickcheck_roundtrip!(Mpz, quickcheck_roundtrip_mpint);

  test_roundtrip!(Mpz, test_mpz_0, 0, vec![0x00, 0x00, 0x00, 0x00]);
  test_roundtrip!(Mpz, test_mpz_1, 1, vec![0x00, 0x00, 0x00, 0x01, 0x01]);
  test_roundtrip!(Mpz, test_mpz_149, 149, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x95]);
  test_roundtrip!(Mpz, test_mpz_36412, 36412, vec![0x00, 0x00, 0x00, 0x03, 0x00, 0x8E, 0x3C]);
  test_roundtrip!(Mpz, test_mpz_ff, 0xFF, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0xFF]);
  test_roundtrip!(Mpz, test_mpz_ffffff, 0xFFFFFFi64, vec![0x00, 0x00, 0x00, 0x04, 0x00, 0xFF, 0xFF, 0xFF]);
  test_roundtrip!(Mpz, test_mpz_neg_1, -1, vec![0x00, 0x00, 0x00, 0x01, 0xFF]);
  test_roundtrip!(Mpz, test_mpz_neg_35, -35, vec![0x00, 0x00, 0x00, 0x01, 0xDD]);
  test_roundtrip!(Mpz, test_mpz_neg_ff, -0xFF, vec![0x00, 0x00, 0x00, 0x02, 0xFF, 0x01]);
  test_roundtrip!(Mpz, test_mpz_neg_ffffffff, -0xFFFFFFFFi64, vec![0x00, 0x00, 0x00, 0x05, 0xFF, 0x00, 0x00, 0x00, 0x01]);

  test_roundtrip!(Mpz, test_mpz_0x9a, 0x9a378f9b2e332a7u64, vec![0x00, 0x00, 0x00, 0x08, 0x09, 0xA3, 0x78, 0xF9, 0xB2, 0xE3, 0x32, 0xA7]);
  test_roundtrip!(Mpz, test_mpz_0x80, 0x80, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
  test_roundtrip!(Mpz, test_mpz_neg_1234, -0x1234, vec![0x00, 0x00, 0x00, 0x02, 0xED, 0xCC]);
  test_roundtrip!(Mpz, test_mpz_neg_0xdeadbeef, -0xDEADBEEFi64, vec![0x00, 0x00, 0x00, 0x05, 0xFF, 0x21, 0x52, 0x41, 0x11]);
}
