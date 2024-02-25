// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::{Mac, Hash, FullLengthMac};
//use parsec_client::core::interface::requests::{Opcode, ResponseStatus, Result};
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::operations::psa_algorithm::*;


// "abcdefghijklmnopqrstuvwxyz012345"
const KEY: [u8; 32] = [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35];
// "hello hmac"
const MESSAGE: [u8; 10] = [0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x6d, 0x61, 0x63];
const SHA256_EXPECTED: [u8; 32] = [0xd5, 0x6e, 0x8b, 0xa2, 0xd4, 0xfd, 0xeb, 0x81, 0x14, 0x11, 0xcd, 0xc5, 0x5a, 0xfa, 0xbe, 0x23, 0x42, 0xb5, 0x16, 0xc4, 0x19, 0x81, 0xc3, 0x51, 0x30, 0xcf, 0xd, 0x15, 0xaf, 0x51, 0x7d, 0x84];



#[test]
fn mac_not_supported() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaMacCompute) {
        assert_eq!(
            client
                .mac_compute(
                    Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha256 }),
                    "some key name",
                    &MESSAGE,
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }

    if !client.is_operation_supported(Opcode::PsaMacVerify) {
        assert_eq!(
            client
                .mac_verify(
                    Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha256 }),
                    "some key name",
                    &MESSAGE,
                    &SHA256_EXPECTED,
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }
}

fn get_attrs(mac: Mac) -> Attributes {
    let permitted_alg = Algorithm::Mac(mac);
    // UsageFlags defined in psa-cryto/src/types/keys.rs, gets re-exported by parsec-client-rust
    let mut usage = UsageFlags::default();
    // set_sign_hash is needed for mac_compute, set_verify_hash is needed for mac_verify
    let _ = usage.set_sign_hash().set_verify_hash();
    // Attributes defined in psa-cryto/src/types/keys.rs, gets re-exported by parsec-client-rust
    let attributes = Attributes {
        key_type: Type::Hmac,
        bits: 256,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags: usage,
            permitted_algorithms: permitted_alg,
        },
    };
    attributes
}


#[test]
fn simple_mac_compute() {
    let key_name = auto_test_keyname!();
    let alg = Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha256 });
    let mut client = TestClient::new();

    // Must be a 32 byte key to match 256 bit key type.
    let _ = client.import_key(key_name.to_string(), get_attrs(alg), KEY.to_vec());

    if !client.is_operation_supported(Opcode::PsaMacCompute) {
        return;
    }

    let mac = client
        .mac_compute(
            alg,
            &key_name,
            &MESSAGE,
        )
        .unwrap();
    assert_eq!(mac, SHA256_EXPECTED);
}

#[test]
fn simple_mac_verify() {
    let key_name = auto_test_keyname!();
    let alg = Mac::FullLength(FullLengthMac::Hmac { hash_alg: Hash::Sha256 });
    let mut client = TestClient::new();

    // Must be a 32 byte key to match 256 bit key type.
    let _ = client.import_key(key_name.to_string(), get_attrs(alg), KEY.to_vec());

    if !client.is_operation_supported(Opcode::PsaMacCompute) {
        return;
    }

    client
        .mac_verify(
            alg,
            &key_name,
            &MESSAGE,
            &SHA256_EXPECTED,
        )
        .unwrap();
}


