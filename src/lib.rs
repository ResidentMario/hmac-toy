use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};
use ecdsa::Signature;
use p256::NistP256;

type HmacSha256 = Hmac<Sha256>;

pub struct IntegrityVerifiedPackage<'a> {
    pub msg: &'a str,
    pub mac: hmac::crypto_mac::Output<HmacSha256>,
}

impl<'a> IntegrityVerifiedPackage<'a> {
    pub fn verify(&self, shared_secret_key: &str) -> bool {
        // In order to verify the integrity of the message, we construct a new MAC for the enclosed
        // message. We then compare this MAC's bytestream against the enclosed MAC's bytestream.
        // If the two do not match, the package has been corrupted or tampered with.
        let mut proposed_mac = HmacSha256::new_varkey(shared_secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        proposed_mac.update(self.msg.as_bytes());
        let pkgd_proposed_mac: hmac::crypto_mac::Output<HmacSha256> = proposed_mac.finalize();
        
        self.mac.eq(&pkgd_proposed_mac)
    }
}

pub fn hmac_encode<'a>(msg: &'a str, shared_secret_key: &str)
    -> IntegrityVerifiedPackage<'a> {
    let mut mac = HmacSha256::new_varkey(shared_secret_key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(msg.as_bytes());

    let pkgd_mac: hmac::crypto_mac::Output<HmacSha256> = mac.finalize();
    IntegrityVerifiedPackage {
        msg: msg,
        mac: pkgd_mac
    }
}
