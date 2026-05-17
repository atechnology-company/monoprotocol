use crate::envelope::{TwoFaMethod, TwoFaProof};
use crate::webauthn::{verify_sms_code, verify_totp_code, verify_webauthn_assertion, WebAuthnRegistry};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TwoFaError {
    #[error("missing 2FA proof")]
    Missing,
    #[error("empty 2FA assertion")]
    EmptyAssertion,
    #[error("unsupported 2FA method")]
    UnsupportedMethod,
    #[error("invalid 2FA assertion")]
    InvalidAssertion,
}

pub fn verify_twofa_proof(proof: &TwoFaProof) -> Result<(), TwoFaError> {
    verify_twofa_proof_with_registry(proof, &WebAuthnRegistry::default(), None)
}

pub fn verify_twofa_proof_with_registry(
    proof: &TwoFaProof,
    registry: &WebAuthnRegistry,
    expected_challenge: Option<&str>,
) -> Result<(), TwoFaError> {
    if proof.assertion.trim().is_empty() {
        return Err(TwoFaError::EmptyAssertion);
    }
    match proof.method {
        TwoFaMethod::WebAuthn => {
            verify_webauthn_assertion(registry, proof, expected_challenge)
        }
        TwoFaMethod::Totp => {
            let secret = std::env::var("MONO_TOTP_SECRET").ok();
            verify_totp_code(&proof.assertion, secret.as_deref())
        }
        TwoFaMethod::Sms => {
            let expected = std::env::var("MONO_SMS_CODE").ok();
            verify_sms_code(&proof.assertion, expected.as_deref())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_six_digits_passes() {
        verify_twofa_proof(&TwoFaProof {
            method: TwoFaMethod::Totp,
            assertion: "123456".into(),
            credential_id: None,
        })
        .unwrap();
    }

    #[test]
    fn totp_wrong_length_fails() {
        assert_eq!(
            verify_twofa_proof(&TwoFaProof {
                method: TwoFaMethod::Totp,
                assertion: "12345".into(),
                credential_id: None,
            }),
            Err(TwoFaError::InvalidAssertion)
        );
    }

    #[test]
    fn sms_six_digits_passes() {
        verify_twofa_proof(&TwoFaProof {
            method: TwoFaMethod::Sms,
            assertion: "654321".into(),
            credential_id: None,
        })
        .unwrap();
    }

    #[test]
    fn empty_assertion_fails() {
        assert_eq!(
            verify_twofa_proof(&TwoFaProof {
                method: TwoFaMethod::Totp,
                assertion: "   ".into(),
                credential_id: None,
            }),
            Err(TwoFaError::EmptyAssertion)
        );
    }
}
