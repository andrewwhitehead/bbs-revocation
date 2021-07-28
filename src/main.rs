use std::{collections::HashSet, fs::File, io::Seek, str::FromStr, time::Instant};

use bbs::issuer::Issuer;
use bbs_revocation::{RegistryBuilder, RegistryReader};
use clap::{App, Arg};
use rand::{distributions::Uniform, rngs::OsRng, Rng};

fn build_test_registry(
    output: &str,
    block_size: u16,
    index_count: u32,
    revoked_perc: f64,
    verify: bool,
) {
    let (issuer_pk, issuer_sk) = Issuer::new_short_keys(None);

    let reg_uri = "urn:my-registry";
    let check_count = 10;
    let revoked_count = ((index_count as f64) * revoked_perc / 100.0) as u32;
    let mut rand_index = OsRng.sample_iter(Uniform::from(0..index_count));
    let mut revoked = HashSet::new();
    let mut r = 0;
    while r < revoked_count {
        if revoked.insert(rand_index.next().unwrap()) {
            r += 1;
        }
    }

    let mut f = File::create(output).expect("Error creating output file");
    let timer = Instant::now();
    let registry = RegistryBuilder::new(reg_uri, block_size, index_count, &issuer_pk, &issuer_sk);
    let entry_count = registry.write(&mut f, revoked.iter().copied()).unwrap();
    f.sync_all().unwrap();
    let reg_size = f.stream_position().unwrap();
    let dur = timer.elapsed();
    drop(f); // close file
    println!(
        "Wrote registry: {} indices, {} revoked in {:0.2}s",
        index_count,
        revoked_count,
        dur.as_secs_f32()
    );
    println!(
        "Registry size: {:0.1}kb, {} entries",
        (reg_size as f64) / 1024.0,
        entry_count,
    );

    if verify {
        let mut f = File::open(output).expect("Error opening registry file");
        let timer = Instant::now();
        let mut reader = RegistryReader::new(&mut f).unwrap();
        let count = reader.entry_count_reset().unwrap();
        let dur = timer.elapsed();
        println!(
            "Read {} non-revocation entries in {:0.2}s",
            count,
            dur.as_secs_f32()
        );
        // for entry in reader {
        //     let e = entry.unwrap();
        //     print!("{}: ", e.level);
        //     for idx in e.unique_indices() {
        //         print!("{} ", idx);
        //     }
        //     print!("\n");
        // }
        // return;

        if revoked_count < index_count {
            for _ in 0..check_count {
                let verkey = reader.public_key();
                let mut check_idx = OsRng.sample(Uniform::from(0..index_count));
                loop {
                    if !revoked.contains(&check_idx) {
                        if let Some(cred) = reader.find_credential_reset(check_idx).unwrap() {
                            let verify = cred.with_messages(|msgs| {
                                cred.signature.verify(&msgs[..], &verkey).unwrap()
                            });
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
                if let Some(check_idx) = rev_iter.next() {
                    if let None = reader.find_credential_reset(check_idx).unwrap() {
                        println!(
                            "Checked: signature missing for revoked index ({})",
                            check_idx
                        );
                    } else {
                        println!("Error: found signature for revoked index ({})", check_idx);
                        return;
                    }
                }
            }
        }

        // verify every entry:
        // for check_idx in 0..index_count {
        //     let sig = reader.find_credential_reset(check_idx).unwrap();
        //     if revoked.contains(&check_idx) && sig.is_some() {
        //         println!("Found invalid signature {}", check_idx);
        //         return;
        //     } else if !revoked.contains(&check_idx) && sig.is_none() {
        //         println!("Missing required signature {}", check_idx);
        //         return;
        //     }
        // }
    }
}

fn main() {
    let mut args_def = App::new("Test Registry Generator")
        .version("0.1")
        .author("Andrew Whitehead <cywolf@gmail.com>")
        .about("Generate test registries for benchmarking")
        .arg(
            Arg::with_name("block-size")
                .long("block-size")
                .short("b")
                .takes_value(true)
                .help("Set the registry block size (multiple of 8, up to 64)")
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .short("o")
                .takes_value(true)
                .help("Output filename (default 'test.reg')"),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .short("c")
                .takes_value(true)
                .required(true)
                .help("Set the registry size"),
        )
        .arg(
            Arg::with_name("percent")
                .long("percent")
                .short("p")
                .takes_value(true)
                .required(true)
                .help("Set the (randomly) revoked percentage of the registry"),
        )
        .arg(
            Arg::with_name("verify")
                .long("verify")
                .short("v")
                .help("Verify the registry"),
        );

    let args = args_def.clone().get_matches();

    let result: Result<(), &str> = (|| {
        let output = args.value_of("output").unwrap_or("test.reg");

        let block_size = args
            .value_of("block-size")
            .and_then(|s| u16::from_str(s).ok())
            .and_then(|b| {
                if b > 0 && b % 8 == 0 && b <= 64 {
                    Some(b)
                } else {
                    None
                }
            })
            .ok_or_else(|| "Block size must be between 8 and 64, and divisible by 8")?;

        let index_count = args
            .value_of("count")
            .and_then(|s| u32::from_str(s).ok())
            .and_then(|c| if c > 0 { Some(c) } else { None })
            .ok_or_else(|| "Count must be an integer larger than zero")?;

        let revoked_perc = args
            .value_of("percent")
            .and_then(|s| u32::from_str(s).ok())
            .and_then(|p| if p <= 100 { Some(p) } else { None })
            .ok_or_else(|| "Revocation percentage must be a positive integer")?;

        let verify = args.is_present("verify");

        build_test_registry(output, block_size, index_count, revoked_perc as f64, verify);
        Ok(())
    })();

    if let Err(err) = result {
        args_def.print_long_help().unwrap();
        println!("\n{}", err);
    }
}
