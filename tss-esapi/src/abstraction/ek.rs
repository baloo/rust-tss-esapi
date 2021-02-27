// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::{nv, DefaultKey, KeyCustomization},
    attributes::ObjectAttributesBuilder,
    constants::tss::*,
    handles::{KeyHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::{
        algorithm::AsymmetricAlgorithm,
        resource_handles::{Hierarchy, NvAuth},
    },
    tss2_esys::{
        TPM2B_ECC_PARAMETER, TPM2B_PUBLIC, TPM2B_PUBLIC_KEY_RSA, TPMS_ECC_PARMS, TPMS_ECC_POINT,
        TPMS_RSA_PARMS, TPMS_SCHEME_HASH, TPMT_ECC_SCHEME, TPMT_KDF_SCHEME, TPMT_RSA_SCHEME,
        TPMT_SYM_DEF_OBJECT, TPMU_ASYM_SCHEME, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE,
    },
    utils::{PublicIdUnion, PublicParmsUnion, Tpm2BPublicBuilder},
    Context, Error, Result, WrapperErrorKind,
};

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Section 2.2.1.4 (Low Range) for Windows compatibility
const RSA_2048_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c00002;
const ECC_P256_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0000a;

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Appendix B.3.3 and B.3.4
fn create_ek_public_from_default_template<K: KeyCustomization>(
    alg: AsymmetricAlgorithm,
    key_customization: &K,
) -> Result<TPM2B_PUBLIC> {
    let obj_attrs_builder = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_st_clear(false)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_no_da(false)
        .with_encrypted_duplication(false)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false);

    let obj_attrs = key_customization.attributes(obj_attrs_builder).build()?;

    // TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
    // With 32 null-bytes attached, because of the type of with_auth_policy
    let authpolicy: [u8; 64] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let key_builder = match alg {
        AsymmetricAlgorithm::Rsa => Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_RSA)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(32, authpolicy)
            .with_parms(PublicParmsUnion::RsaDetail(TPMS_RSA_PARMS {
                symmetric: TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM2_ALG_AES,
                    keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: TPMU_SYM_MODE { aes: TPM2_ALG_CFB },
                },
                scheme: TPMT_RSA_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: Default::default(),
                },
                keyBits: 2048,
                exponent: 0,
            }))
            .with_unique(PublicIdUnion::Rsa(Box::new(TPM2B_PUBLIC_KEY_RSA {
                size: 256,
                buffer: [0; 512],
            }))),
        AsymmetricAlgorithm::Ecc => Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_ECC)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(32, authpolicy)
            .with_parms(PublicParmsUnion::EccDetail(TPMS_ECC_PARMS {
                symmetric: TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM2_ALG_AES,
                    keyBits: TPMU_SYM_KEY_BITS { sym: 128 },
                    mode: TPMU_SYM_MODE { sym: TPM2_ALG_CFB },
                },
                scheme: TPMT_ECC_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: TPMU_ASYM_SCHEME {
                        anySig: TPMS_SCHEME_HASH {
                            hashAlg: TPM2_ALG_NULL,
                        },
                    },
                },
                curveID: TPM2_ECC_NIST_P256,
                kdf: TPMT_KDF_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: Default::default(),
                },
            }))
            .with_unique(PublicIdUnion::Ecc(Box::new(TPMS_ECC_POINT {
                x: TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: [0; 128],
                },
                y: TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: [0; 128],
                },
            }))),
        AsymmetricAlgorithm::Null => {
            // TDOD: Figure out what to with Null.
            return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
        }
    };

    let key_builder = key_customization.template(key_builder);
    key_builder.build()
}

/// Create the Endorsement Key object from the specification templates
pub fn create_ek_object_custom<K: KeyCustomization>(
    context: &mut Context,
    alg: AsymmetricAlgorithm,
    key_customization: &K,
) -> Result<KeyHandle> {
    let ek_public = create_ek_public_from_default_template(alg, key_customization)?;

    Ok(context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, &ek_public, None, None, None, None)
        })?
        .key_handle)
}

/// Create the Endorsement Key object from the specification templates
pub fn create_ek_object(context: &mut Context, alg: AsymmetricAlgorithm) -> Result<KeyHandle> {
    create_ek_object_custom(context, alg, &DefaultKey)
}

/// Retreive the Endorsement Key public certificate from the TPM
pub fn retrieve_ek_pubcert(context: &mut Context, alg: AsymmetricAlgorithm) -> Result<Vec<u8>> {
    let nv_idx = match alg {
        AsymmetricAlgorithm::Rsa => RSA_2048_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithm::Ecc => ECC_P256_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithm::Null => {
            // TDOD: Figure out what to with Null.
            return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
        }
    };

    let nv_idx = NvIndexTpmHandle::new(nv_idx).unwrap();

    let nv_auth_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle = context.execute_without_session(|ctx| {
        ctx.tr_from_tpm_public(nv_auth_handle)
            .map(|v| NvAuth::NvIndex(v.into()))
    })?;

    context.execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))
}
