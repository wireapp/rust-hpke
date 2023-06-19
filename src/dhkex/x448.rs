use crate::{
    dhkex::{DhError, DhKeyExchange},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    util::{enforce_equal_len, KemSuiteId},
    Deserializable, HpkeError, Serializable,
};

use generic_array::{
    typenum::{self, Unsigned},
    GenericArray,
};
use subtle::ConstantTimeEq;

use ed448_goldilocks::{curve::MontgomeryPoint, Scalar};

/// An X448 public key
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicKey(MontgomeryPoint);

/// An X448 private key
#[derive(Clone)]
pub struct PrivateKey(Scalar);

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // We can use to_bytes because StaticSecret is only ever constructed from a clamped scalar
        self.0.to_bytes().ct_eq(&other.0.to_bytes())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for PrivateKey {}

// The underlying type is zeroize-on-drop
/// A bare DH computation result
pub struct KexResult(MontgomeryPoint);

impl Serializable for PublicKey {
    // RFC 9180 §7.1 Table 2: Npk of DHKEM(X448, HKDF-SHA512) is 56
    type OutputSize = typenum::U56;

    // Dalek lets us convert pubkeys to [u8; 56]
    fn to_bytes(&self) -> GenericArray<u8, typenum::U56> {
        GenericArray::clone_from_slice(self.0.as_bytes())
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Pubkeys must be 56 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; 56];
        arr.copy_from_slice(encoded);
        Ok(PublicKey(MontgomeryPoint(arr)))
    }
}

// Compute a public key from a private key
impl From<&PrivateKey> for PublicKey {
    fn from(sk: &PrivateKey) -> Self {
        let point = &MontgomeryPoint::generator() * &sk.0;
        PublicKey(point)
    }
}

impl PrivateKey {
    fn clamp_bytes(bytes: &mut [u8; 56]) {
        bytes[0] &= 252;
        bytes[55] |= 128;
    }
}

// We do this to ensure the raw bytes are always correctly clamped
impl From<[u8; 56]> for PrivateKey {
    fn from(mut bytes: [u8; 56]) -> Self {
        Self::clamp_bytes(&mut bytes);
        Self(ed448_goldilocks::Scalar::from_bytes(bytes))
    }
}

impl Serializable for PrivateKey {
    // RFC 9180 §7.1 Table 2: Nsk of DHKEM(X448, HKDF-SHA512) is 56
    type OutputSize = typenum::U56;

    fn to_bytes(&self) -> GenericArray<u8, typenum::U56> {
        GenericArray::clone_from_slice(&self.0.to_bytes())
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Privkeys must be 56 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; 56];
        arr.copy_from_slice(encoded);

        Ok(PrivateKey::from(arr))
    }
}

impl Serializable for KexResult {
    // RFC 9180 §4.1: For X25519 and X448, the size Ndh is equal to 32 and 56, respectively
    type OutputSize = typenum::U56;

    // curve25519's point representation is our DH result. We don't have to do anything special.
    fn to_bytes(&self) -> GenericArray<u8, typenum::U56> {
        GenericArray::clone_from_slice(self.0.as_bytes())
    }
}

/// Represents ECDH functionality over the X448 group
pub struct X448 {}

impl DhKeyExchange for X448 {
    #[doc(hidden)]
    type PublicKey = PublicKey;
    #[doc(hidden)]
    type PrivateKey = PrivateKey;
    #[doc(hidden)]
    type KexResult = KexResult;

    /// Converts an X448 private key to a public key
    #[doc(hidden)]
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        PublicKey::from(sk)
    }

    /// Does the DH operation. Returns an error if and only if the DH result was all zeros. This is
    /// required by the HPKE spec. The error is converted into the appropriate higher-level error
    /// by the caller, i.e., `HpkeError::EncapError` or `HpkeError::DecapError`.
    #[doc(hidden)]
    fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, DhError> {
        if pk.0.is_low_order() {
            return Err(DhError);
        }

        let shared_key = &pk.0 * &sk.0;
        if shared_key.as_bytes().ct_eq(&[0u8; 56]).into() {
            Err(DhError)
        } else {
            Ok(KexResult(shared_key))
        }
    }

    // RFC 9180 §7.1.3
    // def DeriveKeyPair(ikm):
    //   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
    //   sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
    //   return (sk, pk(sk))

    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have as many bits of entropy as the bit length of a secret
    /// key, i.e., 256.
    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(suite_id: &KemSuiteId, ikm: &[u8]) -> (PrivateKey, PublicKey) {
        // Write the label into a byte buffer and extract from the IKM
        let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);
        // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
        let mut buf = [0u8; 56];
        hkdf_ctx
            .labeled_expand(suite_id, b"sk", &[], &mut buf)
            .unwrap();

        let sk = PrivateKey::from(buf);
        let pk = PublicKey::from(&sk);

        (sk, pk)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dhkex::{
            x448::{PrivateKey, PublicKey, X448},
            Deserializable, DhKeyExchange, Serializable,
        },
        test_util::dhkex_gen_keypair,
    };
    use generic_array::typenum::Unsigned;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    /// Tests that an serialize-deserialize round-trip ends up at the same pubkey
    #[test]
    fn test_pubkey_serialize_correctness() {
        type Kex = X448;

        let mut csprng = StdRng::from_entropy();

        // Fill a buffer with randomness
        let orig_bytes = {
            let mut buf =
                [0u8; <<Kex as DhKeyExchange>::PublicKey as Serializable>::OutputSize::USIZE];
            csprng.fill_bytes(buf.as_mut_slice());
            buf
        };

        // Make a pubkey with those random bytes. Note, that from_bytes() does not clamp the input
        // bytes. This is why this test passes.
        let pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(&orig_bytes).unwrap();
        let pk_bytes = pk.to_bytes();

        // See if the re-serialized bytes are the same as the input
        assert_eq!(orig_bytes.as_slice(), pk_bytes.as_slice());
    }

    /// Tests that an deserialize-serialize round trip on a DH keypair ends up at the same values
    #[test]
    fn test_dh_serialize_correctness() {
        type Kex = X448;

        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and serialize it
        let (sk, pk) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let (sk_bytes, pk_bytes) = (sk.to_bytes(), pk.to_bytes());

        // Now deserialize those bytes
        let new_sk = <Kex as DhKeyExchange>::PrivateKey::from_bytes(&sk_bytes).unwrap();
        let new_pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(&pk_bytes).unwrap();

        // See if the deserialized values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't serialize correctly");
        assert!(new_pk == pk, "public key doesn't serialize correctly");
    }
}
