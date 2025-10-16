//! Cryptographic primitives for attestation
//!
//! Provides signing and verification for integrity proofs.

#[cfg(feature = "remote-attestation")]
use crate::{Error, Result};

#[cfg(feature = "remote-attestation")]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Cryptographic key pair for signing attestations
#[cfg(feature = "remote-attestation")]
pub struct AttestationKeys {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

#[cfg(feature = "remote-attestation")]
impl AttestationKeys {
    /// Generate a new key pair
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| Error::PlatformError("Invalid signature length".into()))?,
        );

        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| Error::PlatformError("Signature verification failed".into()))
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}

#[cfg(test)]
#[cfg(feature = "remote-attestation")]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keys = AttestationKeys::generate();
        assert_eq!(keys.public_key().len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let keys = AttestationKeys::generate();
        let message = b"test message";

        let signature = keys.sign(message);
        assert!(keys.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_invalid() {
        let keys = AttestationKeys::generate();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = keys.sign(message);
        assert!(keys.verify(wrong_message, &signature).is_err());
    }
}
