// Copyright (C) 2026 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transient capture proof and owned file handles; not a persisted snapshot ABI.

use dbs_virtio_devices::capture::WorkerAck;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::sync::Arc;

/// M1 conservatively requires the same KVM-supported CPU/MSR contract.
#[derive(Deserialize, Serialize)]
pub struct CpuRequirements {
    /// Host-supported CPUID leaves at capture time.
    pub cpuid: kvm_bindings::CpuId,
    /// Serializable MSR index set at capture time.
    pub msr_indices: Vec<u32>,
}

/// Open files remain owned across asynchronous VMM requests. No pathname is reopened.
#[derive(Clone, Debug)]
pub struct SnapshotFiles {
    /// Snapshot JSON file. The caller must not mutate it during an operation.
    pub state: Arc<File>,
    /// Packed RAM file. The caller must not mutate it during an operation.
    pub memory: Arc<File>,
}

impl SnapshotFiles {
    /// Transfer ownership of already-open files into the request.
    pub fn new(state: File, memory: File) -> Self {
        Self {
            state: Arc::new(state),
            memory: Arc::new(memory),
        }
    }
}

impl PartialEq for SnapshotFiles {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state) && Arc::ptr_eq(&self.memory, &other.memory)
    }
}

/// Actual host mapping for one packed RAM region. Host addresses are never serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Guest physical base.
    pub guest_addr: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Packed file offset (not a GPA).
    pub file_offset: u64,
    /// Host mapping base.
    pub host_addr: u64,
    /// Registered KVM slot.
    pub kvm_slot: u32,
}

/// Complete RAM layout observed while the VM is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryLayout {
    /// Guest-address ordered mappings.
    pub regions: Vec<MemoryRegion>,
    /// Sum of RAM bytes, excluding GPA holes.
    pub total_bytes: u64,
}

/// Confirmation from a specific vCPU after leaving KVM_RUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcpuAck {
    /// CPU index.
    pub vcpu_id: u8,
    /// Capture generation.
    pub generation: u64,
}

/// Proof for the current transient capture session.
#[derive(Clone, Debug)]
pub struct CaptureReport {
    /// Nonzero session generation.
    pub generation: u64,
    /// Complete CPU acknowledgement set.
    pub vcpu_acks: Vec<VcpuAck>,
    /// Complete activated device-worker acknowledgement set.
    pub device_acks: Vec<WorkerAck>,
    /// Actual host and packed-file mappings.
    pub memory_layout: MemoryLayout,
}

/// A rejected request has not changed a running VM; terminal failures require teardown.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// Invalid request or unsupported configuration before any hold.
    #[error("capture rejected: {0}")]
    Rejected(String),
    /// A CPU/device transition could not be completely confirmed.
    #[error("capture requires VM teardown: {0}")]
    Terminal(String),
    /// Export failed; the current confirmed session remains held.
    #[error("held snapshot export failed: {0}")]
    Export(#[source] super::SnapshotError),
}
