// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::interface_types::ecc::EccCurve;
use crate::structures::{Public, RsaExponent};
use crate::{Error, WrapperErrorKind};

use core::convert::TryFrom;
use oid::ObjectIdentifier;
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{IntegerAsn1, OctetStringAsn1};
use picky_asn1_x509::{
    AlgorithmIdentifier, EcParameters, EcPoint, PublicKey, RsaPublicKey, SubjectPublicKeyInfo,
};
use serde::{Deserialize, Serialize};

/// Can be converted from [`crate::structures::Public`] when not a fully constructed
/// [`picky_asn1_x509::SubjectPublicKeyInfo`] is required.
///
/// # Details
///
/// Holds either [`picky_asn1_x509::RsaPublicKey`] for [`crate::structures::Public::Rsa`] or
/// [`picky_asn1_x509::EcPoint`] for [`crate::structures::Public::Ecc`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DecodedKey {
    RsaPublicKey(RsaPublicKey),
    EcPoint(EcPoint),
}

impl TryFrom<Public> for DecodedKey {
    type Error = Error;

    fn try_from(value: Public) -> Result<Self, Self::Error> {
        public_to_decoded_key(&value)
    }
}

impl TryFrom<Public> for SubjectPublicKeyInfo {
    type Error = Error;

    /// Converts [`crate::structures::Public::Rsa`] and [`crate::structures::Public::Ecc`] to [`picky_asn1_x509::SubjectPublicKeyInfo`].
    ///
    /// # Details
    /// The result can be used to convert TPM public keys to DER using `picky_asn1_der`.
    ///
    /// # Errors
    /// * if other instances of [`crate::structures::Public`] are used `UnsupportedParam` will be returned.
    fn try_from(value: Public) -> Result<Self, Self::Error> {
        let decoded_key = public_to_decoded_key(&value)?;

        match (value, decoded_key) {
            (Public::Rsa { .. }, DecodedKey::RsaPublicKey(key)) => Ok(SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier::new_rsa_encryption(),
                subject_public_key: PublicKey::Rsa(key.into()),
            }),
            (Public::Ecc { parameters, .. }, DecodedKey::EcPoint(point)) => {
                Ok(SubjectPublicKeyInfo {
                    algorithm: AlgorithmIdentifier::new_elliptic_curve(EcParameters::NamedCurve(
                        curve_oid(parameters.ecc_curve())?.into(),
                    )),
                    subject_public_key: PublicKey::Ec(BitString::with_bytes(point).into()),
                })
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

/// Converts [`crate::structures::Public::Rsa`] and [`crate::structures::Public::Ecc`] to [DecodedKey].
///
/// # Details
/// Does basic key conversion to either RSA or ECC. In RSA conversion the TPM zero exponent is replaced with `65537`.
///
/// # Errors
/// * if other instances of [`crate::structures::Public`] are used `UnsupportedParam` will be returned.
fn public_to_decoded_key(public: &Public) -> Result<DecodedKey, Error> {
    match public {
        Public::Rsa {
            unique, parameters, ..
        } => {
            let exponent = match parameters.exponent() {
                RsaExponent::ZERO_EXPONENT => 65537,
                _ => parameters.exponent().value(),
            }
            .to_be_bytes();
            Ok(DecodedKey::RsaPublicKey(RsaPublicKey {
                modulus: IntegerAsn1::from_bytes_be_unsigned(unique.as_bytes().to_vec()),
                public_exponent: IntegerAsn1::from_bytes_be_signed(exponent.to_vec()),
            }))
        }
        Public::Ecc { unique, .. } => {
            let x = unique.x().as_bytes().to_vec();
            let y = unique.y().as_bytes().to_vec();
            Ok(DecodedKey::EcPoint(OctetStringAsn1(
                elliptic_curve_point_to_octet_string(x, y),
            )))
        }

        _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
    }
}

// Taken from https://github.com/parallaxsecond/parsec/blob/561235f3cc37bcff3d9a6cb29c84eeae5d55100b/src/providers/tpm/utils.rs#L319
// Points on elliptic curves are represented as defined in section 2.3.3 of https://www.secg.org/sec1-v2.pdf
// The (uncompressed) representation is [ 0x04 || x || y ] where x and y are the coordinates of the point
fn elliptic_curve_point_to_octet_string(mut x: Vec<u8>, mut y: Vec<u8>) -> Vec<u8> {
    let mut octet_string = vec![0x04];
    octet_string.append(&mut x);
    octet_string.append(&mut y);
    octet_string
}

// Map TPM supported ECC curves to their respective OIDs
fn curve_oid(ecc_curve: EccCurve) -> Result<ObjectIdentifier, Error> {
    match ecc_curve {
        EccCurve::NistP192 => Ok(picky_asn1_x509::oids::secp192r1()),
        EccCurve::NistP224 => Ok(picky_asn1_x509::oids::secp256r1()),
        EccCurve::NistP256 => Ok(picky_asn1_x509::oids::secp256r1()),
        EccCurve::NistP384 => Ok(picky_asn1_x509::oids::secp384r1()),
        EccCurve::NistP521 => Ok(picky_asn1_x509::oids::secp521r1()),
        //  Barreto-Naehrig curves seem to not have any OIDs
        EccCurve::BnP256 => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        EccCurve::BnP638 => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        EccCurve::Sm2P256 => Ok(ObjectIdentifier::try_from("1.2.156.10197.1.301").unwrap()),
    }
}

#[cfg(feature = "rustcrypto")]
mod rustcrypto {
    use crate::{
        interface_types::ecc::EccCurve,
        structures::{Public, RsaExponent},
        Error, WrapperErrorKind,
    };

    use core::convert::TryFrom;
    use p256::elliptic_curve::{
        generic_array::{typenum::Unsigned, GenericArray},
        sec1::FromEncodedPoint,
        Curve,
    };
    use rsa::{BigUint, RsaPublicKey};
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};

    impl TryFrom<Public> for SubjectPublicKeyInfoOwned {
        type Error = Error;

        /// Converts [`crate::structures::Public::Rsa`] and [`crate::structures::Public::Ecc`] to [`spki::SubjectPublicKeyInfo`].
        ///
        /// # Details
        /// The result can be used to convert TPM public keys to DER using `picky_asn1_der`.
        ///
        /// # Errors
        /// * if other instances of [`crate::structures::Public`] are used `UnsupportedParam` will be returned.
        fn try_from(public: Public) -> Result<Self, Self::Error> {
            match public {
                Public::Rsa {
                    unique, parameters, ..
                } => {
                    let exponent = match parameters.exponent() {
                        RsaExponent::ZERO_EXPONENT => BigUint::from(65537u32),
                        e => BigUint::from(e.value()),
                    };
                    let modulus = BigUint::from_bytes_be(unique.as_bytes());

                    let pub_key = RsaPublicKey::new(modulus, exponent)
                        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;

                    Ok(pub_key
                        .to_public_key_der()
                        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?
                        .decode_msg::<SubjectPublicKeyInfoOwned>()
                        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?)
                }

                Public::Ecc {
                    parameters, unique, ..
                } => {
                    let curve = parameters.ecc_curve();

                    let x = unique.x().as_bytes();
                    let y = unique.x().as_bytes();

                    macro_rules! get_key_ecdsa {
                        ($crypto_root:ident, $curve:ty) => {{
                            let x = if x.len() == <$curve as Curve>::FieldBytesSize::USIZE {
                                GenericArray::from_slice(x)
                            } else {
                                return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                            };

                            let y = if y.len() == <$curve as Curve>::FieldBytesSize::USIZE {
                                GenericArray::from_slice(y)
                            } else {
                                return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                            };

                            let point =
                                ::$crypto_root::EncodedPoint::from_affine_coordinates(x, y, false);

                            // `into` degrades the constant time option in a regular option, but
                            // we're talking public keys here, I don't think we need the constant
                            // time guarantees.
                            let key: Option<::$crypto_root::PublicKey> =
                                ::$crypto_root::PublicKey::from_encoded_point(&point).into();
                            let key =
                                key.ok_or(Error::local_error(WrapperErrorKind::InvalidParam))?;

                            Ok(key
                                .to_public_key_der()
                                .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?
                                .decode_msg::<SubjectPublicKeyInfoOwned>()
                                .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?)
                        }};
                    }

                    match curve {
                        EccCurve::NistP256 => get_key_ecdsa!(p256, p256::NistP256),
                        EccCurve::NistP384 => get_key_ecdsa!(p384, p384::NistP384),
                        _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
                    }
                }

                _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            }
        }
    }
}
