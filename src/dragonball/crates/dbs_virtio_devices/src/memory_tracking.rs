// Copyright (C) 2026 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dirty tracking for device writers which bypass vm-memory's volatile slices.

use vm_memory::{bitmap::Bitmap, Address, GuestAddress, GuestMemory};

/// Mark a completely validated guest write, including region boundaries.
pub fn mark_guest_write<M: GuestMemory + ?Sized>(
    mem: &M,
    addr: GuestAddress,
    len: usize,
) -> crate::Result<()> {
    if addr.checked_add(len as u64).is_none() || !mem.check_range(addr, len) {
        return Err(crate::Error::InvalidOffset);
    }
    for slice in mem.get_slices(addr, len) {
        let slice = slice.map_err(crate::Error::GuestMemory)?;
        slice.bitmap().mark_dirty(0, slice.len());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::persist::VirtioQueueState;
    use crate::VirtioQueueConfig;
    use std::ops::Deref;
    use virtio_queue::QueueSync;
    use vm_memory::{
        bitmap::{AtomicBitmap, Bitmap},
        Bytes, GuestMemoryMmap, GuestMemoryRegion,
    };

    pub(crate) fn queue(base: u64, index: u16) -> VirtioQueueConfig<QueueSync> {
        let mut queue = VirtioQueueConfig::create(16, index).unwrap();
        VirtioQueueState {
            max_size: 16,
            size: 16,
            ready: true,
            desc_table: base,
            avail_ring: base + 0x1000,
            used_ring: base + 0x2000,
            ..Default::default()
        }
        .restore(queue.queue_mut())
        .unwrap();
        queue
    }

    pub(crate) fn descriptor<M: GuestMemory>(
        mem: &M,
        table: u64,
        index: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let offset = table + u64::from(index) * 16;
        mem.write_obj(addr, GuestAddress(offset)).unwrap();
        mem.write_obj(len, GuestAddress(offset + 8)).unwrap();
        mem.write_obj(flags, GuestAddress(offset + 12)).unwrap();
        mem.write_obj(next, GuestAddress(offset + 14)).unwrap();
    }

    #[test]
    fn m2_raw_write_crosses_region_boundary() {
        let memory = GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[
            (GuestAddress(0), 4096),
            (GuestAddress(4096), 4096),
            (GuestAddress(0x3000), 4096),
        ])
        .unwrap();
        mark_guest_write(&memory, GuestAddress(4090), 20).unwrap();
        assert!(memory.iter().next().unwrap().bitmap().dirty_at(4090));
        assert!(memory.iter().nth(1).unwrap().bitmap().dirty_at(0));
        assert!(!memory.iter().nth(2).unwrap().bitmap().dirty_at(0));
        for region in memory.iter() {
            region.deref().bitmap().reset();
        }
        assert!(mark_guest_write(&memory, GuestAddress(4090), 8192).is_err());
        assert!(mark_guest_write(&memory, GuestAddress(u64::MAX), 2).is_err());
        assert!(memory.iter().all(|region| !region.bitmap().dirty_at(0)));
    }
}
