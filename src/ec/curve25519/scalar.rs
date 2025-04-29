// Copyright 2015-2019 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::{
    trace_log,
    arithmetic::limbs_from_hex,
    digest, error, limb,
    polyfill::slice::{self, AsChunks},
};
use core::array;

use zeroize::Zeroize;

#[repr(transparent)]
pub struct Scalar([u8; SCALAR_LEN]);

pub const SCALAR_LEN: usize = 32;

impl zeroize::ZeroizeOnDrop for Scalar {} // Marker
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
//        let bytes = unsafe { std::slice::from_raw_parts(self.0.as_ptr() as *const u8, SCALAR_LIMBS * 4) };
//        let needs_zero = !is_all_zeros(bytes);
        #[cfg(feature = "trace_drop_and_zeroize")] {
            let needs_zero = !crate::is_all_zeros(&self.0);
            trace_log!("!!!! before zeroize-ing X25519 Scalar, needs zeroize: {}", needs_zero);
        }
        self.0.zeroize();
        assert!(crate::is_all_zeros(&self.0), "X25519 Scalar not zeroized");
        trace_log!("!!!! after zeroize-ing X25519 Scalar");
//        trace_log!("Zeroized X25519 Scalar, needs_zero: {}", needs_zero);
//        assert!(is_all_zeros(bytes), "X25519 Scalar not zeroized");
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        trace_log!("!!! before dropping X25519 Scalar");
        self.zeroize();
        trace_log!("!!! after dropping X25519 Scalar");
    }
}

impl Scalar {
    // Constructs a `Scalar` from `bytes`, failing if `bytes` encodes a scalar
    // that is not in the range [0, n).
    pub fn from_bytes_checked(bytes: [u8; SCALAR_LEN]) -> Result<Self, error::Unspecified> {
        const ORDER: [limb::Limb; SCALAR_LEN / limb::LIMB_BYTES] =
            limbs_from_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
        let order = ORDER.map(limb::Limb::from);

        let (limbs_as_bytes, _empty): (AsChunks<u8, { limb::LIMB_BYTES }>, _) =
            slice::as_chunks(&bytes);
        debug_assert!(_empty.is_empty());
        let limbs: [limb::Limb; SCALAR_LEN / limb::LIMB_BYTES] =
            array::from_fn(|i| limb::Limb::from_le_bytes(limbs_as_bytes[i]));
        limb::verify_limbs_less_than_limbs_leak_bit(&limbs, &order)?;

        Ok(Self(bytes))
    }

    // Constructs a `Scalar` from `digest` reduced modulo n.
    pub fn from_sha512_digest_reduced(digest: digest::Digest) -> Self {
        prefixed_extern! {
            fn x25519_sc_reduce(s: &mut UnreducedScalar);
        }
        let mut unreduced = [0u8; digest::SHA512_OUTPUT_LEN];
        unreduced.copy_from_slice(digest.as_ref());
        unsafe { x25519_sc_reduce(&mut unreduced) };
        Self((&unreduced[..SCALAR_LEN]).try_into().unwrap())
    }
}

#[repr(transparent)]
pub struct MaskedScalar([u8; SCALAR_LEN]);

impl zeroize::ZeroizeOnDrop for MaskedScalar {} // Marker
impl Zeroize for MaskedScalar {
    fn zeroize(&mut self) {
        #[cfg(feature = "trace_drop_and_zeroize")] {
            let needs_zero = !crate::is_all_zeros(&self.0);
            trace_log!("!!!! before zeroized MaskedScalar, needs zeroize: {}", needs_zero);
        }
        self.0.zeroize();
        assert!(crate::is_all_zeros(&self.0), "MaskedScalar not zeroized");
        trace_log!("!!!! after zeroized MaskedScalar");
    }
}

impl Drop for MaskedScalar {
    fn drop(&mut self) {
        trace_log!("!!! before dropping MaskedScalar");
        self.zeroize();
        trace_log!("!!! after dropping MaskedScalar");
    }
}

impl MaskedScalar {
    pub fn from_bytes_masked(bytes: [u8; SCALAR_LEN]) -> Self {
        prefixed_extern! {
            fn x25519_sc_mask(a: &mut [u8; SCALAR_LEN]);
        }
        let mut r = Self(bytes);
        unsafe { x25519_sc_mask(&mut r.0) };
        r
    }
}

impl From<MaskedScalar> for Scalar {
    fn from(MaskedScalar(scalar): MaskedScalar) -> Self {
        Self(scalar)
    }
}

type UnreducedScalar = [u8; UNREDUCED_SCALAR_LEN];
const UNREDUCED_SCALAR_LEN: usize = SCALAR_LEN * 2;
