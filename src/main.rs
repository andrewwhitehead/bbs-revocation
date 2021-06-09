use std::fs::File;

use bbs::issuer::Issuer;

use crate::registry::{RegistryBuilder, RegistryReader};

mod registry;

fn main() {
    let (issuer_pk, issuer_sk) = Issuer::new_short_keys(None);

    let reg_uri = "urn:my-registry";
    let reg_size = 100000;
    let registry = RegistryBuilder::<64>::new(reg_uri, reg_size, &issuer_pk, &issuer_sk);

    let mut f = File::create("test.reg").expect("Error creating output file");
    registry.write(&mut f, std::iter::empty::<u32>()).unwrap();
    f.sync_all().unwrap();
    drop(f);

    let mut f = File::open("test.reg").expect("Error opening registry file");
    let reader = RegistryReader::new(&mut f).unwrap();
    let _ = reader.find_signature(0).unwrap();
}
