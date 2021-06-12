use std::{
    collections::HashSet,
    fs::File,
    io::{Seek, SeekFrom},
    time::Instant,
};

use bbs::issuer::Issuer;
use bbs_revocation::{compute_index_message, RegistryBuilder, RegistryReader};
use rand::{distributions::Uniform, rngs::OsRng, Rng};

fn main() {
    let (issuer_pk, issuer_sk) = Issuer::new_short_keys(None);

    let reg_uri = "urn:my-registry";
    let index_count = 100000;
    let check_count = 100;
    let revoked_perc = 1.0;
    let revoked_count = ((index_count as f64) * revoked_perc / 100.0) as u32;
    let mut rand_index = OsRng.sample_iter(Uniform::from(0..index_count));
    let mut revoked = HashSet::new();
    let mut r = 0;
    while r < revoked_count {
        if revoked.insert(rand_index.next().unwrap()) {
            r += 1;
        }
    }

    let mut f = File::create("test.reg").expect("Error creating output file");
    let start = Instant::now();
    let registry = RegistryBuilder::<64>::new(reg_uri, index_count, &issuer_pk, &issuer_sk);
    let entry_count = registry.write(&mut f, revoked.iter().copied()).unwrap();
    f.sync_all().unwrap();
    let reg_size = f.stream_position().unwrap();
    let dur = Instant::now() - start;
    drop(f);
    println!(
        "Wrote registry: {} indices, {} revoked, {} non-revocation entries in {:0.2}s",
        index_count,
        revoked_count,
        entry_count,
        dur.as_secs_f32()
    );
    println!("Registry size: {}kb", reg_size / 1024);

    let mut f = File::open("test.reg").expect("Error opening registry file");
    let start = Instant::now();
    let reader = RegistryReader::new(&mut f).unwrap();
    let count = reader.entries::<64>().unwrap().count();
    let dur = Instant::now() - start;
    println!(
        "Read {} non-revocation entries in {:0.2}s",
        count,
        dur.as_secs_f32()
    );

    if revoked_count < index_count {
        for _ in 0..check_count {
            f.seek(SeekFrom::Start(0)).unwrap();
            let reader = RegistryReader::new(&mut f).unwrap();
            let header_messages = reader.header().signature_messages();
            let verkey = reader.public_key().unwrap();
            let mut check_idx = OsRng.sample(Uniform::from(0..index_count));
            loop {
                if !revoked.contains(&check_idx) {
                    if let Some((ids, level, sig)) = reader.find_signature(0).unwrap() {
                        let mut messages = Vec::with_capacity(68);
                        messages.extend(&header_messages[..]);
                        for index in ids {
                            messages.push(compute_index_message(index, level));
                        }
                        let verify = sig.verify(messages.as_slice(), &verkey).unwrap();
                        if verify {
                            println!(
                                "Checked: signature verifies for non-revoked index ({})",
                                check_idx
                            );
                        } else {
                            println!(
                                "Error: signature verification failed for non-revoked index ({})",
                                check_idx
                            );
                            return;
                        }
                    } else {
                        println!(
                            "Error: signature not found for non-revoked index ({})",
                            check_idx
                        );
                        return;
                    }
                    break;
                }
                check_idx = (check_idx + 1) % index_count;
            }
        }
    }

    if !revoked.is_empty() {
        let mut rev_iter = revoked.iter().copied();
        for _ in 0..check_count {
            f.seek(SeekFrom::Start(0)).unwrap();
            let reader = RegistryReader::new(&mut f).unwrap();
            if let Some(idx) = rev_iter.next() {
                if let None = reader.find_signature(idx).unwrap() {
                    println!("Checked: signature missing for revoked index ({})", idx);
                } else {
                    println!("Error: found signature for revoked index ({})", idx);
                    return;
                }
            }
        }
    }
}
