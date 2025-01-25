//! HD wallet key derivation functionality.

// This code is copied and modified from the `hd-wallet` crate.

use hd_wallet::{
    DeriveShift, DerivedShift, ExtendedKeyPair, ExtendedPublicKey, HardenedIndex, NonHardenedIndex,
};

use super::Ristretto255;

/// HD derivation for [`Ristretto255`].
pub struct HdWallet {
    _private: (),
}

impl DeriveShift<Ristretto255> for HdWallet {
    fn derive_public_shift(
        parent_public_key: &ExtendedPublicKey<Ristretto255>,
        child_index: NonHardenedIndex,
    ) -> DerivedShift<Ristretto255> {
        let hmac = HmacSha512::new_from_slice(&parent_public_key.chain_code)
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .chain_update(parent_public_key.public_key.to_bytes(true))
            // we append 0 byte to the public key for compatibility with other libs
            .chain_update([0x00])
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift(parent_public_key, i)
    }

    fn derive_hardened_shift(
        parent_key: &ExtendedKeyPair<Ristretto255>,
        child_index: HardenedIndex,
    ) -> DerivedShift<Ristretto255> {

    }
}

impl HdWallet {
    fn calculate_shift(
        parent_public_key: &ExtendedPublicKey<curves::Ed25519>,
        i: hmac::digest::Output<HmacSha512>,
    ) -> DerivedShift<curves::Ed25519> {
        let (i_left, i_right) = split_into_two_halves(&i);

        let shift = Scalar::from_be_bytes_mod_order(i_left);
        let child_pk = parent_public_key.public_key + Point::generator() * shift;

        DerivedShift {
            shift,
            child_public_key: ExtendedPublicKey {
                public_key: child_pk,
                chain_code: (*i_right).into(),
            },
        }
    }
}

/// Splits array `I` of 64 bytes into two arrays `I_L = I[..32]` and `I_R = I[32..]`
fn split_into_two_halves(
    i: &generic_array::GenericArray<u8, generic_array::typenum::U64>,
) -> (
    &generic_array::GenericArray<u8, generic_array::typenum::U32>,
    &generic_array::GenericArray<u8, generic_array::typenum::U32>,
) {
    generic_array::sequence::Split::split(i)
}
