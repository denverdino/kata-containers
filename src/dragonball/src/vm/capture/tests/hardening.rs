// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn backend_oversized_state_is_rejected_before_decode() {
    let vm = super::super::super::tests::create_vm_instance();
    let state = TempFile::new().unwrap();
    let memory = TempFile::new().unwrap();
    state.as_file().set_len(64 * 1024 * 1024 + 1).unwrap();
    memory.as_file().set_len(16 << 20).unwrap();
    let error = vm
        .read_held_snapshot(&files(&state, &memory))
        .err()
        .expect("oversized state must be rejected");
    assert!(
        error.to_string().contains("state exceeds"),
        "oversized state must be rejected before JSON decoding: {}",
        error
    );
    assert!(vm.vm_as().is_none());
}

#[test]
fn backend_expired_ram_export_keeps_output_and_dirty_history() {
    let (mut vm, _real) = paused_counter_vm();
    let ram = vm.address_space.vm_memory().unwrap();
    ram.write_slice(&[0x71; 4096], GuestAddress(0x5000))
        .unwrap();
    vm.begin_capture(1, deadline()).unwrap();
    let state = TempFile::new().unwrap();
    let memory = TempFile::new().unwrap();
    memory
        .as_file()
        .write_all_at(b"previous output", 0)
        .unwrap();
    let result = vm
        .address_space
        .save_held_memory(&vm.vm_fd, 1, memory.as_file(), Instant::now());
    if result.is_ok() {
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        panic!("expired export must fail");
    }
    let error = result.err().unwrap();
    assert!(
        matches!(&error, crate::address_space_manager::AddressManagerError::SnapshotFile(source)
            if source.kind() == std::io::ErrorKind::TimedOut),
        "expected deadline error, got {:?}",
        error
    );
    assert_eq!(std::fs::read(memory.as_path()).unwrap(), b"previous output");
    assert!(vm.capture_session.as_ref().unwrap().report.is_some());
    assert!(vm.end_capture(1, Instant::now(), false).is_err());
    vm.export_held_snapshot(1, deadline(), &files(&state, &memory))
        .unwrap();
    let mut page = [0; 4096];
    memory.as_file().read_exact_at(&mut page, 0x5000).unwrap();
    assert_eq!(page, [0x71; 4096]);
    vm.end_capture(1, deadline(), false).unwrap();
    vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
}

#[test]
fn backend_state_writer_enforces_size_and_expired_deadline() {
    let mut writer = StateWriter {
        output: std::io::sink(),
        remaining: MAX_STATE_BYTES,
        deadline: deadline(),
    };
    let chunk = vec![0; 1 << 20];
    for _ in 0..64 {
        writer.write_all(&chunk).unwrap();
    }
    assert_eq!(
        writer.write(&[1]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    let mut writer = StateWriter {
        output: b"untouched".to_vec(),
        remaining: MAX_STATE_BYTES,
        deadline: Instant::now(),
    };
    assert_eq!(
        writer.write(&[1]).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(writer.output, b"untouched");
}

#[test]
fn backend_invalid_restore_state_never_executes_or_allocates_ram() {
    let (mut source, real) = paused_counter_vm();
    let config = source.vm_config.clone();
    let state = TempFile::new().unwrap();
    let memory = TempFile::new().unwrap();
    let input = files(&state, &memory);
    source.begin_capture(1, deadline()).unwrap();
    source.export_held_snapshot(1, deadline(), &input).unwrap();
    source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    drop(real);
    drop(source);
    let original = std::fs::read(state.as_path()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    for mutation in 0..12 {
        let mut changed = value.clone();
        match mutation {
            0 => changed["header"]["format_epoch"] = serde_json::json!(65537),
            1 => changed["vcpu_states"] = serde_json::json!([]),
            2 => changed["vcpu_states"][0]["id"] = serde_json::json!(255),
            3 => changed["vcpu_states"]
                .as_array_mut()
                .unwrap()
                .push(value["vcpu_states"][0].clone()),
            4 => changed["vm_kvm_state"] = serde_json::Value::Null,
            5 => changed["memory_state"]["regions"] = serde_json::json!([]),
            6 => changed["memory_state"]["regions"][0]["size"] = serde_json::json!(u64::MAX),
            7 => changed["memory_state"]["regions"][0]["file_offset"] = serde_json::json!(4096),
            8 => changed["memory_state"]["regions"]
                .as_array_mut()
                .unwrap()
                .push(value["memory_state"]["regions"][0].clone()),
            9 => changed["device_states"]["unknown_writer"] = serde_json::json!({"active":true}),
            10 => changed["capture_cpu"]["msr_indices"] = serde_json::json!([u32::MAX]),
            _ => changed["memory_state"]["regions"][0]["guest_addr"] = serde_json::json!(1),
        }
        std::fs::write(state.as_path(), serde_json::to_vec(&changed).unwrap()).unwrap();
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll).unwrap();
        let mut guard = vmm.lock().unwrap();
        let target = guard.get_vm_mut().unwrap();
        let real = RealVcpuExecution::new(target.vm_fd.clone());
        target.set_vm_config(config.clone());
        let result =
            target.load_snapshot_held(&mut events, Default::default(), &input, 1, deadline());
        assert!(result.is_err(), "mutation {} unexpectedly loaded", mutation);
        assert!(
            target.vm_as().is_none(),
            "mutation {} allocated guest RAM",
            mutation
        );
        assert_eq!(real.run_count(), 0);
        if matches!(result, Err(CaptureError::Rejected(_))) {
            std::fs::write(state.as_path(), &original).unwrap();
            target
                .load_snapshot_held(&mut events, Default::default(), &input, 2, deadline())
                .unwrap();
            assert_eq!(real.run_count(), 0);
            target.end_capture(2, deadline(), false).unwrap();
            target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        } else {
            assert!(target
                .load_snapshot_held(&mut events, Default::default(), &input, 2, deadline())
                .is_err());
        }
    }
}

fn descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn assert_unmapped(file: &File) {
    let info = file.metadata().unwrap();
    for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let inode: u64 = fields[4].parse().unwrap();
        let (major, minor) = fields[3].split_once(':').unwrap();
        let device = libc::makedev(
            u32::from_str_radix(major, 16).unwrap(),
            u32::from_str_radix(minor, 16).unwrap(),
        );
        assert!(
            inode != info.ino() || device != info.dev(),
            "snapshot mapping leaked: {}",
            line
        );
    }
}

#[cfg(feature = "virtio-balloon")]
#[test]
fn backend_seeded_cow_reclaim_and_failed_export_cycles() {
    const NAME: &str =
        "vm::capture::tests::hardening::backend_seeded_cow_reclaim_and_failed_export_cycles";
    if std::env::var_os("KATA_BACKEND_CYCLE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env("KATA_BACKEND_CYCLE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!("seeded memory oracle: 64 fresh restores, seed=0x62a9dff713058b4c; child passed");
        return;
    }
    let (mut source, real) = paused_counter_vm();
    let config = source.vm_config.clone();
    let ram = source.address_space.vm_memory().unwrap();
    ram.write_slice(&[0x51; 4096], GuestAddress(8 << 20))
        .unwrap();
    let state = TempFile::new().unwrap();
    let memory = TempFile::new().unwrap();
    let mut input = files(&state, &memory);
    source.begin_capture(1, deadline()).unwrap();
    source.export_held_snapshot(1, deadline(), &input).unwrap();
    source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    drop(ram);
    drop(real);
    drop(source);
    let mut expected = vec![0; 16 << 20];
    input.memory.read_exact_at(&mut expected, 0).unwrap();
    let mut seed = 0x62a9_dff7_1305_8b4cu64;
    let mut baseline = None;
    for cycle in 0..64 {
        let ancestor = expected.clone();
        let output = {
            let epoll = EpollManager::default();
            let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
                epoll.clone(),
            )));
            let mut events = EventManager::new(&vmm, epoll).unwrap();
            let mut guard = vmm.lock().unwrap();
            let target = guard.get_vm_mut().unwrap();
            let real = RealVcpuExecution::new(target.vm_fd.clone());
            target.set_vm_config(config.clone());
            target
                .load_snapshot_held(&mut events, Default::default(), &input, 1, deadline())
                .unwrap();
            let ram = target.address_space.vm_memory().unwrap();
            let previous = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
            target.end_capture(1, deadline(), true).unwrap();
            let limit = deadline();
            while ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap() == previous
                && Instant::now() < limit
            {
                std::thread::yield_now();
            }
            target.begin_capture(2, deadline()).unwrap();
            let counter = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
            assert_ne!(counter, previous);
            assert!(real.run_count() > 0);
            expected[0x2000..0x2002].copy_from_slice(&counter.to_le_bytes());
            let reclaimer = crate::address_space_manager::PrivateMemoryReclaimer::new(
                target.vm_as().cloned().unwrap(),
                target.vm_address_space().cloned().unwrap(),
            );
            for operation in 0..8 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let offset = (4 << 20) + (seed as usize % 512) * 4096;
                let bytes = [if operation % 3 == 0 {
                    0
                } else {
                    (seed >> 32) as u8
                }; 4096];
                ram.write_slice(&bytes, GuestAddress(offset as u64))
                    .unwrap();
                expected[offset..offset + 4096].copy_from_slice(&bytes);
                if operation % 2 == 0 {
                    reclaimer
                        .reclaim_private_range(offset as u64, 4096)
                        .unwrap();
                    expected[offset..offset + 4096].fill(0);
                }
            }
            let next_state = TempFile::new().unwrap();
            let next_memory = TempFile::new().unwrap();
            let mut invalid = files(&next_state, &next_memory);
            invalid.memory = Arc::new(File::open(next_memory.as_path()).unwrap());
            assert!(matches!(
                target.export_held_snapshot(2, deadline(), &invalid),
                Err(CaptureError::Export(_))
            ));
            assert!(target.end_capture(3, deadline(), true).is_err());
            target
                .export_held_memory_map_without_zero_scan(2, deadline())
                .unwrap();
            assert!(target.end_capture(2, deadline(), true).is_err());
            let output = files(&next_state, &next_memory);
            target.export_held_snapshot(2, deadline(), &output).unwrap();
            target.release_held_memory_map(2).unwrap();
            target.end_capture(2, deadline(), false).unwrap();
            target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
            output
        };
        let mut actual = vec![0; expected.len()];
        output.memory.read_exact_at(&mut actual, 0).unwrap();
        assert!(actual == expected, "memory mismatch in cycle {}", cycle);
        input.memory.read_exact_at(&mut actual, 0).unwrap();
        assert!(actual == ancestor, "ancestor changed in cycle {}", cycle);
        assert_unmapped(&input.memory);
        input = output;
        let count = descriptor_count();
        assert_eq!(
            *baseline.get_or_insert(count),
            count,
            "descriptor growth in cycle {}",
            cycle
        );
    }
}
