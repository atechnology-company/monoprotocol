use serde::{Deserialize, Serialize};

/// Sensitivity tier; drives encryption, 2FA, replication, and relay policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferClass {
    PublicMetadata,
    PrivateState,
    SensitiveSession,
    HardwareBoundSecret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPolicy {
    pub encryption_required: bool,
    pub twofa_required_to_apply: bool,
    pub relay_may_store_ciphertext: bool,
    pub gossip_allowed: bool,
    pub p2p_preferred: bool,
    pub revocation_invalidates: bool,
    pub agent_may_read_metadata: bool,
    pub agent_may_read_payload: bool,
}

impl TransferClass {
    pub fn policy(self) -> TransferPolicy {
        match self {
            Self::PublicMetadata => TransferPolicy {
                encryption_required: false,
                twofa_required_to_apply: false,
                relay_may_store_ciphertext: true,
                gossip_allowed: true,
                p2p_preferred: true,
                revocation_invalidates: true,
                agent_may_read_metadata: true,
                agent_may_read_payload: true,
            },
            Self::PrivateState => TransferPolicy {
                encryption_required: true,
                twofa_required_to_apply: false,
                relay_may_store_ciphertext: true,
                gossip_allowed: true,
                p2p_preferred: true,
                revocation_invalidates: true,
                agent_may_read_metadata: true,
                agent_may_read_payload: false,
            },
            Self::SensitiveSession => TransferPolicy {
                encryption_required: true,
                twofa_required_to_apply: true,
                relay_may_store_ciphertext: true,
                gossip_allowed: true,
                p2p_preferred: true,
                revocation_invalidates: true,
                agent_may_read_metadata: true,
                agent_may_read_payload: false,
            },
            Self::HardwareBoundSecret => TransferPolicy {
                encryption_required: true,
                twofa_required_to_apply: true,
                relay_may_store_ciphertext: false,
                gossip_allowed: false,
                p2p_preferred: false,
                revocation_invalidates: true,
                agent_may_read_metadata: false,
                agent_may_read_payload: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_session_requires_twofa() {
        assert!(TransferClass::SensitiveSession.policy().twofa_required_to_apply);
        assert!(TransferClass::SensitiveSession.policy().encryption_required);
    }

    #[test]
    fn hardware_bound_blocks_relay_and_gossip() {
        let p = TransferClass::HardwareBoundSecret.policy();
        assert!(!p.relay_may_store_ciphertext);
        assert!(!p.gossip_allowed);
    }

    #[test]
    fn all_transfer_classes_policy_matrix() {
        let cases = [
            (
                TransferClass::PublicMetadata,
                false,
                false,
                true,
                true,
                true,
                true,
            ),
            (
                TransferClass::PrivateState,
                true,
                false,
                true,
                true,
                true,
                false,
            ),
            (
                TransferClass::SensitiveSession,
                true,
                true,
                true,
                true,
                true,
                false,
            ),
            (
                TransferClass::HardwareBoundSecret,
                true,
                true,
                false,
                false,
                false,
                false,
            ),
        ];
        for (class, enc, twofa, relay, gossip, agent_meta, agent_payload) in cases {
            let p = class.policy();
            assert_eq!(p.encryption_required, enc, "{class:?} encryption");
            assert_eq!(p.twofa_required_to_apply, twofa, "{class:?} twofa");
            assert_eq!(p.relay_may_store_ciphertext, relay, "{class:?} relay");
            assert_eq!(p.gossip_allowed, gossip, "{class:?} gossip");
            assert_eq!(p.agent_may_read_metadata, agent_meta, "{class:?} agent meta");
            assert_eq!(p.agent_may_read_payload, agent_payload, "{class:?} agent payload");
        }
    }
}
