use serde::{Deserialize, Serialize};

use crate::ids::IdentityId;

/// Who logically owns replicated state (always the user identity).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "owner")]
pub enum StateOwner {
    Identity { identity_id: IdentityId },
}

/// Where bytes may physically reside; distinct from ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateResidency {
    /// Cupboard / mono-gateway encrypted blob store
    Cupboard,
    /// Tableware: rendezvous, presence, queue hints only
    TablewareCoordination,
    /// Hot path in browser engine profile
    BrowserProfile,
    /// Ephemeral peer during Atmosphere P2P handoff
    MeshPeer,
    /// Content-addressed cache on any device
    LocalContentCache,
}
