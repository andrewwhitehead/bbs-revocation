pub use bbs::{
    keys::{DeterministicPublicKey, PublicKey, SecretKey},
    signature::{Signature, SIGNATURE_COMPRESSED_SIZE},
    SignatureMessage, G1_COMPRESSED_SIZE,
};

mod block;

mod builder;
pub use self::builder::RegistryBuilder;

mod header;
pub use self::header::RegistryHeader;

mod reader;
pub use self::reader::RegistryReader;

mod util;

pub const SIG_HEADER_MESSAGES: usize = 4;

#[test]
fn test_registry_cycle() {
    use std::io::Cursor;

    let (dpk, sk) = DeterministicPublicKey::new(None);
    let mut buf = Vec::new();
    let mut c = Cursor::new(&mut buf);
    let reg = RegistryBuilder::<64>::new("test:uri", 5, &dpk, &sk).timestamp(1000);
    reg.write(&mut c, [0].iter().copied()).unwrap();
    // 208 (header size) + 8 (entries length) + 8 (entry header) + 8 (bit array) + 48 (signature)
    assert_eq!(buf.len(), 280);

    let mut c = Cursor::new(&mut buf);
    let reader = RegistryReader::new(&mut c).unwrap();
    let header = reader.header().clone();
    assert_eq!(header.type_.as_ref(), "bbs-registry;v=1");
    assert_eq!(header.uri.as_ref(), "test:uri");
    assert_eq!(header.block_size, 64);
    assert_eq!(header.levels, 2);
    let entries = reader
        .entries::<64>()
        .unwrap()
        .map(|e| e.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);

    let mut c = Cursor::new(&mut buf);
    let reader = RegistryReader::new(&mut c).unwrap();
    let sig = reader.find_signature(0).unwrap();
    // index 0 was revoked
    assert!(sig.is_none());

    let mut c = Cursor::new(&mut buf);
    let reader = RegistryReader::new(&mut c).unwrap();
    let sig = reader.find_signature(1).unwrap();
    // index 1 was not revoked
    assert!(sig.is_some());
}
