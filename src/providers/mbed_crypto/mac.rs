// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use parsec_interface::operations::{psa_mac_compute, psa_mac_verify};
use parsec_interface::requests::{ResponseStatus, Result};
use psa_crypto::operations::mac;
use psa_crypto::types::key;

impl Provider {
    pub(super) fn psa_mac_compute_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_mac_compute::Operation,
    ) -> Result<psa_mac_compute::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );
        let key_id = self.key_info_store.get_key_id(&key_identity)?;
        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");
        let id = key::Id::from_persistent_key_id(key_id)?;
        let key_attributes = key::Attributes::from_key_id(id)?;
        op.validate(key_attributes)?;

        // ????????? Is this right?  How should I otherwise estimate
        // the vector size. If the vector isn't big enough mbedtls
        // complains.
        let mut mac = vec![0u8;key_attributes.bits/8];

        match mac::compute_mac(id, op.alg, &op.input, &mut mac) {
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
        application_identity: &ApplicationIdentity,
        op: psa_mac_verify::Operation,
    ) -> Result<psa_mac_verify::Result> {
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            op.key_name.clone(),
        );
        let key_id = self.key_info_store.get_key_id(&key_identity)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let id = key::Id::from_persistent_key_id(key_id)?;
        let key_attributes = key::Attributes::from_key_id(id)?;
        op.validate(key_attributes)?;

        match mac::verify_mac(id, op.alg, &op.input, &op.mac) {
            Ok(()) => Ok(psa_mac_verify::Result),
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("MAC verify status: ", error);
                Err(error)
            }
        }
    }
}
