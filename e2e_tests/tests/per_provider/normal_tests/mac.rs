// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
//use parsec_client::core::interface::operations::psa_algorithm::Mac;
//use parsec_client::core::interface::requests::{Opcode, ResponseStatus, Result};
use parsec_client::core::interface::requests::Opcode;

#[test]
fn mac_supported() {
    let mut client = TestClient::new();
    println!("Provider: {}", client.provider());
    let oc = client.list_opcodes(client.provider());
    println!("Supported OpCodes: {:?}", oc);
    assert!(client.is_operation_supported(Opcode::PsaMacCompute));
    assert!(client.is_operation_supported(Opcode::PsaMacVerify));
}
