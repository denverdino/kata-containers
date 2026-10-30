// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//! Selected separately from required native regressions by the diagnostic lane.

use super::capture::tests::paused_counter_vm_with_disk_slot;
use crate::snapshot::capture::SnapshotFiles;
use slog::Drain;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::{Duration, Instant};
use vm_memory::{Bytes, GuestAddress};
use vmm_sys_util::tempfile::TempFile;

fn cpu_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // The kernel writes the owned timespec on success.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) },
        0
    );
    value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}

fn io() -> std::collections::BTreeMap<String, u64> {
    std::fs::read_to_string("/proc/thread-self/io")
        .unwrap()
        .lines()
        .map(|line| {
            let (name, value) = line.split_once(": ").unwrap();
            (name.to_string(), value.parse().unwrap())
        })
        .collect()
}

#[test]
fn backend_export_io_profile() {
    let drain = slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(std::io::stderr()))
        .build()
        .fuse();
    let drain = slog::LevelFilter::new(drain, slog::Level::Info).fuse();
    let _logger = slog_scope::set_global_logger(slog::Logger::root(drain, slog::o!()));
    slog_stdlog::init().unwrap();
    let directory = std::env::temp_dir();
    for profile in ["sparse", "contiguous", "fragmented"] {
        let (mut vm, _real) = paused_counter_vm_with_disk_slot(None, false, 512);
        let ram = vm.address_space.vm_memory().unwrap();
        let mut expected = vec![0; 512 << 20];
        // Observe only initialized low memory; leave untouched guest pages sparse.
        ram.read_slice(&mut expected[..1 << 20], GuestAddress(0))
            .unwrap();
        let stride = if profile == "fragmented" { 8192 } else { 4096 };
        let pages = if profile == "sparse" { 4096 } else { 16384 };
        for index in 0..pages {
            let offset = (4 << 20) + index * stride;
            let page = [(index % 251 + 1) as u8; 4096];
            ram.write_slice(&page, GuestAddress(offset as u64)).unwrap();
            expected[offset..offset + 4096].copy_from_slice(&page);
        }
        vm.begin_capture(1, Instant::now() + Duration::from_secs(10))
            .unwrap();
        for trial in 0..6 {
            let state = TempFile::new_in(&directory).unwrap();
            let memory = TempFile::new_in(&directory).unwrap();
            let files = SnapshotFiles::new(
                state.as_file().try_clone().unwrap(),
                memory.as_file().try_clone().unwrap(),
            );
            let before_io = io();
            let before_cpu = cpu_ns();
            let started = Instant::now();
            vm.export_held_snapshot(1, Instant::now() + Duration::from_secs(10), &files)
                .unwrap();
            let elapsed = started.elapsed();
            let cpu = cpu_ns() - before_cpu;
            let after_io = io();
            let mut actual = vec![0; expected.len()];
            files.memory.read_exact_at(&mut actual, 0).unwrap();
            assert!(actual == expected, "{} export changed RAM bytes", profile);
            let metadata = files.memory.metadata().unwrap();
            let counters: std::collections::BTreeMap<_, _> = after_io
                .iter()
                .map(|(name, value)| (name, value - before_io[name]))
                .collect();
            eprintln!(
                "EXPORT_DIAGNOSTIC {}",
                serde_json::json!({
                    "profile": profile, "trial": trial, "warmup": trial == 0,
                    "elapsed_us": elapsed.as_micros() as u64, "cpu_us": cpu / 1000,
                    "logical_bytes": metadata.len(), "allocated_bytes": metadata.blocks() * 512,
                    "io": counters, "byte_oracle": true,
                })
            );
        }
        vm.end_capture(1, Instant::now() + Duration::from_secs(10), false)
            .unwrap();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    }
}
