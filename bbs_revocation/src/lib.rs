pub use bbs::{
    keys::{DeterministicPublicKey, PublicKey, SecretKey},
    signature::{Signature, SIGNATURE_COMPRESSED_SIZE},
    SignatureMessage, G1_COMPRESSED_SIZE,
};

mod block;
pub use block::MESSAGES_MAX;

mod builder;
pub use self::builder::RegistryBuilder;

mod header;
pub use self::header::{RegistryHeader, HEADER_MESSAGES};

mod reader;
pub use self::reader::{NonRevCredential, RegistryReader};

mod util;
pub use self::util::compute_index_message;

#[test]
fn test_registry_cycle() {
    use std::io::Cursor;

    let block_size = 64;
    let (dpk, sk) = DeterministicPublicKey::new(None);
    let mut buf = Vec::new();
    let mut c = Cursor::new(&mut buf);
    let reg = RegistryBuilder::new("test:uri", block_size, 5, &dpk, &sk).timestamp(1000);
    reg.write(&mut c, [0].iter().copied()).unwrap();
    // 208 (header size) + 8 (entries length) + 8 (entry header) + 8 (bit array) + 48 (signature)
    assert_eq!(buf.len(), 280);

    let mut c = Cursor::new(&mut buf);
    let mut reader = RegistryReader::new(&mut c).unwrap();
    let header = reader.header().clone();
    assert_eq!(header.registry_type.as_ref(), "bbs-registry;v=1");
    assert_eq!(header.registry_uri.as_ref(), "test:uri");
    assert_eq!(header.timestamp, 1000);
    assert_eq!(header.interval, 0);
    assert_eq!(header.block_size, block_size);
    assert_eq!(header.levels, 2);
    let entries = reader.entry_count_reset().unwrap();
    assert_eq!(entries, 1);

    let cred = reader.find_credential_reset(0).unwrap();
    // index 0 was revoked
    assert!(cred.is_none());

    let cred = reader.find_credential_reset(1).unwrap();
    // index 1 was not revoked
    assert!(cred.is_some());
}

#[test]
fn test_cred_zkp() {
    use bbs::{pm_hidden_raw, pm_revealed_raw, prelude::*};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Cursor;
    use std::iter::FromIterator;

    let block_size = 16;
    let slot_index = 1;
    let (dpk, sk) = DeterministicPublicKey::new(None);

    // generate initial registry
    let mut reg_buf = Vec::new();
    let mut c = Cursor::new(&mut reg_buf);
    let reg = RegistryBuilder::new("test:uri", block_size, 5, &dpk, &sk).timestamp(1000);
    reg.write(&mut c, std::iter::empty()).unwrap();

    // load registry
    let mut c = Cursor::new(&mut reg_buf);
    let mut reader = RegistryReader::new(&mut c).unwrap();

    // issue a credential from the registry
    let issued_msg_count = HEADER_MESSAGES + 3;
    let mut issued_msgs = Vec::with_capacity(issued_msg_count);
    issued_msgs.extend(reader.header().messages().iter().copied());
    issued_msgs.push(compute_index_message(slot_index, 0));
    issued_msgs.push(compute_index_message(slot_index / (block_size as u32), 1));
    issued_msgs.push(SignatureMessage::hash(b"Sterling Archer"));

    let issued_pk = dpk.to_public_key(issued_msg_count).unwrap();
    let issued_sig = Signature::new(&issued_msgs[..], &sk, &issued_pk).unwrap();
    assert!(issued_sig.verify(&issued_msgs[..], &issued_pk).unwrap());

    // create PoK of signature for issued cred
    let same_blinding = ProofNonce::random();
    let mut proof_messages_1 = Vec::with_capacity(issued_msg_count);
    let mut issued_reveal = BTreeMap::new();
    let mut issued_reveal_idx = BTreeSet::new();
    for (idx, msg) in issued_msgs.iter().copied().enumerate() {
        if idx < HEADER_MESSAGES {
            issued_reveal_idx.insert(proof_messages_1.len());
            issued_reveal.insert(proof_messages_1.len(), msg);
            proof_messages_1.push(pm_revealed_raw!(msg));
        } else if idx == HEADER_MESSAGES {
            // slot index
            proof_messages_1.push(pm_hidden_raw!(msg, same_blinding));
        } else if idx == HEADER_MESSAGES + 1 {
            // block index
            proof_messages_1.push(pm_hidden_raw!(msg));
        } else {
            // revealed statement(s)
            issued_reveal_idx.insert(proof_messages_1.len());
            issued_reveal.insert(proof_messages_1.len(), msg);
            proof_messages_1.push(pm_revealed_raw!(msg));
        }
    }
    let pok_issued = PoKOfSignature::init(&issued_sig, &issued_pk, &proof_messages_1[..]).unwrap();

    // Find non-revocation credential and generate PoK of signature
    let nr_cred = reader.find_credential_reset(slot_index).unwrap().unwrap();
    let nrc_pk = nr_cred.public_key();
    let (pok_nrc, nrc_compare_index) = nr_cred.create_pok_of_signature(&nrc_pk, same_blinding);
    let nrc_revealed_idx = BTreeSet::from_iter(0..HEADER_MESSAGES);
    let nrc_header = BTreeMap::from_iter(nr_cred.header_messages().iter().cloned().enumerate());

    // Prover generates the challenge
    let mut chal_bytes = Vec::new();
    chal_bytes.append(&mut pok_issued.to_bytes());
    chal_bytes.append(&mut pok_nrc.to_bytes());
    let chal_prover = ProofChallenge::hash(&chal_bytes);

    let proof_1 = pok_issued.gen_proof(&chal_prover).unwrap();
    let proof_2 = pok_nrc.gen_proof(&chal_prover).unwrap();
    println!(
        "Proof sizes: {}, {}",
        proof_1.to_bytes_compressed_form().len(),
        // 256 + (block_size * 32) bytes
        proof_2.to_bytes_compressed_form().len()
    );

    // The verifier generates the challenge on its own
    let mut chal_bytes = Vec::new();
    chal_bytes.append(&mut proof_1.get_bytes_for_challenge(issued_reveal_idx, &issued_pk));
    chal_bytes.append(&mut proof_2.get_bytes_for_challenge(nrc_revealed_idx, &nrc_pk));
    let chal_verifier = ProofChallenge::hash(&chal_bytes);

    // Response for the same message should be same (this check is made by the verifier)
    assert_eq!(
        // slot_index is the first hidden message (index `HEADER_MESSAGES` in the credential)
        proof_1.get_resp_for_message(0).unwrap(),
        // hidden message index in the non-revocation credential
        proof_2.get_resp_for_message(nrc_compare_index).unwrap()
    );
    // Sanity check second index fails
    assert_ne!(
        proof_1.get_resp_for_message(1).unwrap(),
        proof_2.get_resp_for_message(nrc_compare_index).unwrap()
    );
    assert!(proof_1
        .verify(&issued_pk, &issued_reveal, &chal_verifier)
        .unwrap()
        .is_valid());
    assert!(proof_2
        .verify(&nrc_pk, &nrc_header, &chal_verifier)
        .unwrap()
        .is_valid());
}
