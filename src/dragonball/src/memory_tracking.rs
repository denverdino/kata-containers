// Copyright (C) 2026 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transient, generation-scoped RAM read maps. Host addresses are never persisted.

/// One guest mapping in the packed RAM image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenMemoryRegion {
    /// Guest physical address.
    pub guest_base: u64,
    /// Host virtual address, valid only while the owning generation is pinned.
    pub host_base: u64,
    /// Packed image offset, excluding guest physical holes.
    pub image_offset: u64,
    /// Region byte length.
    pub length: u64,
}

/// A page-aligned interval in the packed image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRange {
    /// Packed image offset.
    pub image_offset: u64,
    /// Interval byte length.
    pub length: u64,
}

/// Read proof for a held generation; never a durable snapshot record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenMemoryMap {
    /// Capture generation that owns this map.
    pub generation: u64,
    /// Tracking page size in bytes.
    pub page_size: u64,
    /// Complete fixed RAM layout.
    pub regions: Vec<FrozenMemoryRegion>,
    /// Cumulative changes since cold start or the last load.
    pub changed_ranges: Vec<MemoryRange>,
    /// Currently zero pages, always a subset of changed ranges.
    pub zero_ranges: Vec<MemoryRange>,
}

/// Fixed-base cumulative pages; ordinary captures never reset this bitmap.
#[derive(Default)]
pub(crate) struct MemoryTracker {
    words: Vec<u64>,
}

impl MemoryTracker {
    pub(crate) fn new(bytes: u64, restored: bool) -> Self {
        Self {
            words: vec![
                if restored { 0 } else { u64::MAX };
                ((bytes / 4096).div_ceil(64)) as usize
            ],
        }
    }

    pub(crate) fn merge(&mut self, image_offset: u64, length: u64, bitmap: &[u64]) {
        let first = image_offset / 4096;
        for page in 0..length / 4096 {
            if bitmap[(page / 64) as usize] & (1 << (page % 64)) != 0 {
                let index = first + page;
                self.words[(index / 64) as usize] |= 1 << (index % 64);
            }
        }
    }

    pub(crate) fn dirty(&self, image_offset: u64) -> bool {
        let page = image_offset / 4096;
        self.words[(page / 64) as usize] & (1 << (page % 64)) != 0
    }
}

pub(crate) fn push_page(ranges: &mut Vec<MemoryRange>, offset: u64) {
    if let Some(last) = ranges.last_mut() {
        if last.image_offset + last.length == offset {
            last.length += 4096;
            return;
        }
    }
    ranges.push(MemoryRange {
        image_offset: offset,
        length: 4096,
    });
}
