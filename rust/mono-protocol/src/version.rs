use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ids::DeviceId;

/// Per-device logical clocks for merge and conflict detection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionVector {
    pub clocks: HashMap<String, u64>,
}

impl VersionVector {
    pub fn bump(&mut self, device_id: &DeviceId) {
        let entry = self.clocks.entry(device_id.0.clone()).or_insert(0);
        *entry += 1;
    }

    pub fn merge(&mut self, other: &VersionVector) {
        for (device, clock) in &other.clocks {
            let entry = self.clocks.entry(device.clone()).or_insert(0);
            *entry = (*entry).max(*clock);
        }
    }

    pub fn dominates(&self, other: &VersionVector) -> bool {
        other.clocks.iter().all(|(device, clock)| {
            self.clocks.get(device).copied().unwrap_or(0) >= *clock
        })
    }
}
