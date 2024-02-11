// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use parsec_interface::operations::{psa_mac_verify, psa_mac_compute};
use parsec_interface::requests::{ResponseStatus, Result};
use psa_crypto::operations::mac;

impl Provider {
    pub(super) fn psa_mac_compute_internal(
        &self,
        op: psa_mac_compute::Operation,
    ) -> Result<psa_mac_compute::Result> {
        let mut mac = vec![0u8];

        match mac::mac_compute(&op.key_name, op.alg, &op.input, &mut mac) {
            Ok(mac_size) => {
                mac.resize(mac_size, 0);
                Ok(psa_mac_compute::Result { mac: mac.into() })
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Has compute status: ", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_mac_verify_internal(
        &self,
        op: psa_mac_verify::Operation,
    ) -> Result<psa_mac_verify::Result> {
        match mac::mac_verify(&op.key_name, op.alg, &op.input, &op.mac) {
            Ok(()) => Ok(psa_mac_verify::Result),
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("MAC verify status: ", error);
                Err(error)
            }
        }
    }
}
