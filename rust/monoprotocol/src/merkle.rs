use serde::{Deserialize, Serialize};

use crate::content::ContentHash;

/// Merkle DAG node for content-addressed encrypted objects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: ContentHash,
    pub parents: Vec<ContentHash>,
    pub object_id: String,
    pub transfer_class: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: ContentHash,
    pub path: Vec<ContentHash>,
    pub root: ContentHash,
}

impl MerkleNode {
    pub fn seal(
        object_id: &str,
        transfer_class: &str,
        payload: &[u8],
        parents: Vec<ContentHash>,
    ) -> Self {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(object_id.as_bytes());
        hasher_input.extend_from_slice(transfer_class.as_bytes());
        hasher_input.extend_from_slice(payload);
        for p in &parents {
            hasher_input.extend_from_slice(&p.0);
        }
        Self {
            hash: ContentHash::hash(&hasher_input),
            parents,
            object_id: object_id.to_string(),
            transfer_class: transfer_class.to_string(),
        }
    }
}
