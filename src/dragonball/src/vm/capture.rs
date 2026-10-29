// Copyright (C) 2026 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::device_manager::capture::DeviceCaptureError;
use crate::snapshot::capture::{CaptureError, CaptureReport, CpuRequirements, SnapshotFiles};
use crate::snapshot::{MicrovmState, SnapshotError};
use dbs_snapshot::Persist;
use dbs_virtio_devices::capture::CaptureGeneration;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::{MutexGuard, TryLockError};
use std::time::Instant;

type CaptureResult<T> = std::result::Result<T, CaptureError>;

use crate::memory_tracking::FrozenMemoryMap;

pub(super) struct VmCaptureSession {
    generation: u64,
    report: Option<CaptureReport>,
    read_map: Option<(bool, FrozenMemoryMap)>,
}

fn terminal(error: impl std::fmt::Display) -> CaptureError {
    CaptureError::Terminal(error.to_string())
}

fn same_file(left: &File, right: &File) -> std::io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn host_cpu_requirements(
    kvm: &KvmContext,
) -> std::result::Result<kvm_bindings::CpuId, SnapshotError> {
    let mut cpuid = kvm
        .supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .map_err(SnapshotError::Kvm)?;
    for entry in cpuid.as_mut_slice() {
        // Initial physical APIC ID depends on the host CPU running the ioctl,
        // not on compatibility. Retain all feature, model and geometry bits.
        if entry.function == 1 {
            entry.ebx &= 0x00ff_ffff;
        }
        if matches!(entry.function, 0x0b | 0x1f) {
            entry.edx = 0;
        }
    }
    Ok(cpuid)
}

impl Vm {
    /// Export a generation-owned read map.
    pub fn export_held_memory_map(
        &mut self,
        generation: u64,
        deadline: Instant,
    ) -> CaptureResult<FrozenMemoryMap> {
        self.export_held_memory_map_with_zero_scan(generation, deadline, true)
    }

    /// Export the same layout and cumulative dirty ranges without reading RAM
    /// to classify zeros. Consumers must copy changed zero pages explicitly.
    pub fn export_held_memory_map_without_zero_scan(
        &mut self,
        generation: u64,
        deadline: Instant,
    ) -> CaptureResult<FrozenMemoryMap> {
        self.export_held_memory_map_with_zero_scan(generation, deadline, false)
    }

    fn export_held_memory_map_with_zero_scan(
        &mut self,
        generation: u64,
        deadline: Instant,
        classify_zeros: bool,
    ) -> CaptureResult<FrozenMemoryMap> {
        let layout = self
            .held_report(generation, deadline)?
            .memory_layout
            .clone();
        if self
            .address_space
            .capture_layout()
            .map_err(|e| CaptureError::Export(e.into()))?
            != layout
        {
            return Err(terminal("held memory layout changed"));
        }
        if let Some((classified, map)) = &self.capture_session.as_ref().unwrap().read_map {
            if !classify_zeros || *classified {
                let mut map = map.clone();
                if !classify_zeros {
                    map.zero_ranges.clear();
                }
                return Ok(map);
            }
        }
        let map = self
            .address_space
            .frozen_memory_map(&self.vm_fd, generation, classify_zeros)
            .map_err(|e| CaptureError::Export(e.into()))?;
        if Instant::now() >= deadline {
            return Err(CaptureError::Rejected(
                "memory export deadline expired; session remains held".into(),
            ));
        }
        self.capture_session.as_mut().unwrap().read_map = Some((classify_zeros, map.clone()));
        Ok(map)
    }

    /// Release the current generation's memory read pin.
    pub fn release_held_memory_map(&mut self, generation: u64) -> CaptureResult<()> {
        let session = self
            .capture_session
            .as_mut()
            .ok_or_else(|| CaptureError::Rejected("no capture session".into()))?;
        if generation == 0 || session.generation != generation || session.report.is_none() {
            return Err(CaptureError::Rejected(
                "wrong or unconfirmed generation".into(),
            ));
        }
        session.read_map = None;
        Ok(())
    }

    /// Export metadata without copying RAM.
    pub fn export_held_state(
        &mut self,
        generation: u64,
        deadline: Instant,
        file: &File,
    ) -> CaptureResult<()> {
        let expected = self
            .held_report(generation, deadline)?
            .memory_layout
            .clone();
        let export = (|| -> std::result::Result<(), SnapshotError> {
            if !file.metadata()?.is_file() {
                return Err(SnapshotError::InvalidSnapshot(
                    "state output must be a regular file".into(),
                ));
            }
            self.validate_state_output(file)?;
            let state = self.held_snapshot_metadata(&expected, deadline)?;
            let mut output = file.try_clone()?;
            output.seek(SeekFrom::Start(0))?;
            output.set_len(0)?;
            let mut writer = BufWriter::new(output);
            serde_json::to_writer(&mut writer, &state)
                .map_err(crate::snapshot::PersistError::from)?;
            writer.flush()?;
            file.sync_all()?;
            if Instant::now() >= deadline {
                return Err(SnapshotError::InvalidState(
                    "export deadline expired; session remains held".into(),
                ));
            }
            Ok(())
        })();
        export.map_err(CaptureError::Export)
    }

    fn held_snapshot_metadata(
        &mut self,
        expected: &crate::snapshot::capture::MemoryLayout,
        deadline: Instant,
    ) -> std::result::Result<MicrovmState, SnapshotError> {
        if self.address_space.capture_layout()? != *expected {
            return Err(SnapshotError::InvalidSnapshot(
                "held memory layout changed".into(),
            ));
        }
        let msrs = self.kvm.supported_msrs(0).map_err(SnapshotError::Kvm)?;
        let states = self
            .capture_cpu_manager(deadline)
            .map_err(|e| SnapshotError::InvalidState(e.to_string()))?
            .capture_save(msrs.as_slice(), deadline)?;
        let mut state = self.snapshot_metadata_paused(states, false)?;
        state.capture_cpu = Some(CpuRequirements {
            cpuid: host_cpu_requirements(&self.kvm)?,
            msr_indices: msrs.as_slice().to_vec(),
        });
        state.memory_state = Some(crate::address_space_manager::GuestMemoryState {
            regions: expected
                .regions
                .iter()
                .map(
                    |region| crate::address_space_manager::GuestMemoryRegionState {
                        guest_addr: region.guest_addr,
                        size: region.size,
                        file_offset: region.file_offset,
                    },
                )
                .collect(),
        });
        Ok(state)
    }

    fn validate_state_output(&self, file: &File) -> std::result::Result<(), SnapshotError> {
        use vm_memory::GuestMemory;
        #[cfg(feature = "virtio-pmem")]
        if self
            .device_manager
            .pmem_manager
            .output_aliases_backing(file)?
        {
            return Err(SnapshotError::InvalidSnapshot(
                "output aliases live pmem backing".into(),
            ));
        }
        if let Some(source) = &self.capture_source {
            if same_file(file, &source.state)? || same_file(file, &source.memory)? {
                return Err(SnapshotError::InvalidSnapshot(
                    "output aliases live snapshot backing".into(),
                ));
            }
        }
        if let Some(memory) = self.address_space.vm_memory() {
            for region in memory.iter() {
                if let Some(backing) = region.file_offset() {
                    if same_file(file, backing.file())? {
                        return Err(SnapshotError::InvalidSnapshot(
                            "output aliases live RAM mapping".into(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) fn capture_is_active(&self) -> bool {
        self.capture_session.is_some()
    }
    fn capture_cpu_manager(&self, deadline: Instant) -> CaptureResult<MutexGuard<'_, VcpuManager>> {
        let manager = self
            .vcpu_manager
            .as_ref()
            .ok_or_else(|| terminal("missing vCPU manager"))?;
        loop {
            if Instant::now() >= deadline {
                return Err(terminal("vCPU manager deadline expired"));
            }
            match manager.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(TryLockError::Poisoned(_)) => return Err(terminal("vCPU manager poisoned")),
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            }
        }
    }

    fn validate_capture_request(&self, generation: u64, deadline: Instant) -> CaptureResult<()> {
        if self.capture_session.is_some() {
            return Err(terminal("capture session already active"));
        }
        if generation == 0
            || generation <= self.last_capture_generation
            || Instant::now() >= deadline
        {
            return Err(CaptureError::Rejected(
                "invalid generation or expired deadline".into(),
            ));
        }
        if self.confidential_vm_type().is_some()
            || self.vm_config.vcpu_count != self.vm_config.max_vcpu_count
        {
            return Err(CaptureError::Rejected(
                "confidential VMs and CPU hotplug are not qualified".into(),
            ));
        }
        if self.vm_fd.check_extension_int(kvm_ioctls::Cap::Xsave2)
            > std::mem::size_of::<kvm_bindings::kvm_xsave>() as i32
        {
            return Err(CaptureError::Rejected(
                "extended XSAVE buffers are not qualified".into(),
            ));
        }
        Ok(())
    }

    /// Stop CPUs and every supported device writer, retaining a generation proof.
    pub fn begin_capture(
        &mut self,
        generation: u64,
        deadline: Instant,
    ) -> CaptureResult<CaptureReport> {
        self.validate_capture_request(generation, deadline)?;
        let initial = self.instance_state();
        if !matches!(initial, InstanceState::Running | InstanceState::Paused) {
            return Err(CaptureError::Rejected(format!(
                "invalid VM state {initial:?}"
            )));
        }
        self.device_manager
            .preflight_capture(deadline)
            .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        let layout = self
            .address_space
            .capture_layout()
            .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        self.last_capture_generation = generation;
        // Install before sending anything: timeouts/disconnections cannot undo uncertain holds.
        self.capture_session = Some(VmCaptureSession {
            generation,
            report: None,
            read_map: None,
        });
        let vcpu_acks = self
            .capture_cpu_manager(deadline)?
            .capture_pause(generation, deadline)
            .map_err(terminal)?;
        self.shared_info.write().unwrap().state = InstanceState::Paused;
        let device_acks = match self
            .device_manager
            .begin_capture(CaptureGeneration(generation), deadline)
        {
            Ok(acks) => acks,
            Err(DeviceCaptureError::Rejected(error)) => {
                if initial == InstanceState::Running {
                    self.capture_cpu_manager(deadline)?
                        .capture_resume(generation, deadline)
                        .map_err(terminal)?;
                    self.shared_info.write().unwrap().state = InstanceState::Running;
                }
                self.capture_session = None;
                return Err(CaptureError::Rejected(error));
            }
            Err(error) => return Err(terminal(error)),
        };
        let report = CaptureReport {
            generation,
            vcpu_acks,
            device_acks,
            memory_layout: layout,
        };
        self.capture_session.as_mut().unwrap().report = Some(report.clone());
        Ok(report)
    }

    fn held_report(&self, generation: u64, deadline: Instant) -> CaptureResult<&CaptureReport> {
        let session = self
            .capture_session
            .as_ref()
            .ok_or_else(|| CaptureError::Rejected("no capture session".into()))?;
        if session.generation != generation || generation == 0 || Instant::now() >= deadline {
            return Err(CaptureError::Rejected(
                "wrong generation or expired deadline".into(),
            ));
        }
        session
            .report
            .as_ref()
            .ok_or_else(|| terminal("capture was not completely confirmed"))
    }

    /// Release the original device set, then explicitly resume CPUs if requested.
    pub fn end_capture(
        &mut self,
        generation: u64,
        deadline: Instant,
        resume: bool,
    ) -> CaptureResult<()> {
        self.held_report(generation, deadline)?;
        if self.capture_session.as_ref().unwrap().read_map.is_some() {
            return Err(CaptureError::Rejected(
                "memory readers still pin this generation".into(),
            ));
        }
        // Mark unconfirmed before release; any partial release requires teardown.
        self.capture_session.as_mut().unwrap().report = None;
        self.device_manager
            .end_capture(CaptureGeneration(generation), deadline)
            .map_err(terminal)?;
        if resume {
            self.capture_cpu_manager(deadline)?
                .capture_resume(generation, deadline)
                .map_err(terminal)?;
            self.shared_info.write().unwrap().state = InstanceState::Running;
        }
        self.capture_session = None;
        Ok(())
    }

    /// Export complete packed RAM and metadata through owned open files, never paths.
    pub fn export_held_snapshot(
        &mut self,
        generation: u64,
        deadline: Instant,
        files: &SnapshotFiles,
    ) -> CaptureResult<()> {
        let expected = self
            .held_report(generation, deadline)?
            .memory_layout
            .clone();
        let export = (|| -> std::result::Result<(), SnapshotError> {
            if !files.state.metadata()?.is_file()
                || !files.memory.metadata()?.is_file()
                || same_file(&files.state, &files.memory)?
            {
                return Err(SnapshotError::InvalidSnapshot(
                    "outputs must be distinct regular files".into(),
                ));
            }
            // Linux pwrite appends on O_APPEND descriptors, ignoring its offset.
            // SAFETY: the file stays open and F_GETFL takes no additional argument.
            let flags = unsafe { libc::fcntl(files.memory.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if flags & libc::O_APPEND != 0 {
                return Err(SnapshotError::InvalidSnapshot(
                    "memory output must not use append mode".into(),
                ));
            }
            for output in [&files.state, &files.memory] {
                self.validate_state_output(output)?;
            }
            let mut state = self.held_snapshot_metadata(&expected, deadline)?;
            state.memory_state = Some(self.address_space.save_held_memory(
                &self.vm_fd,
                generation,
                &files.memory,
            )?);
            let mut output = files.state.try_clone()?;
            output.seek(SeekFrom::Start(0))?;
            output.set_len(0)?;
            let mut writer = BufWriter::new(output);
            serde_json::to_writer(&mut writer, &state)
                .map_err(crate::snapshot::PersistError::from)?;
            writer.flush()?;
            files.memory.sync_all()?;
            files.state.sync_all()?;
            if Instant::now() >= deadline {
                return Err(SnapshotError::InvalidState(
                    "export deadline expired; session remains held".into(),
                ));
            }
            Ok(())
        })();
        export.map_err(CaptureError::Export)
    }

    /// Restore to a held state; no vCPU enters KVM_RUN and no device consumes a queue.
    pub fn load_snapshot_held(
        &mut self,
        events: &mut EventManager,
        filters: HashMap<String, BpfProgram>,
        files: &SnapshotFiles,
        generation: u64,
        deadline: Instant,
    ) -> CaptureResult<CaptureReport> {
        let started = Instant::now();
        self.validate_capture_request(generation, deadline)?;
        if self.is_vm_initialized() {
            return Err(CaptureError::Rejected("VM is already initialized".into()));
        }
        let mut slots = std::collections::HashSet::new();
        for binding in &files.block_bindings {
            if !slots.insert(&binding.slot_id) {
                return Err(CaptureError::Rejected(
                    "duplicate restore slot binding".into(),
                ));
            }
            self.device_manager
                .block_manager
                .restore_slot_binding(binding)
                .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        }
        #[cfg(feature = "virtio-pmem")]
        self.device_manager
            .pmem_manager
            .set_restore_bindings(&files.pmem_bindings)
            .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        self.device_manager
            .validate_capture_profile()
            .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        let state = self
            .read_held_snapshot(files)
            .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        let decoded_us = started.elapsed().as_micros() as u64;
        let (mut memory_us, mut vcpu_manager_us, mut devices_us, mut state_us, mut events_us) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        self.last_capture_generation = generation;
        self.capture_session = Some(VmCaptureSession {
            generation,
            report: None,
            read_map: None,
        });
        self.capture_source = Some(files.clone());
        let restored = (|| -> std::result::Result<(), StartMicroVmError> {
            if let Some(filter) = filters.get(ALL_THREADS) {
                if let Err(e) = apply_filter_all_threads(filter) {
                    if !matches!(e, SecError::EmptyFilter) {
                        return Err(StartMicroVmError::SeccompFilters(e));
                    }
                }
            }
            self.shared_info.write().unwrap().state = InstanceState::Starting;
            self.init_guest_memory_with_snapshot(Some((
                state.memory_state.as_ref().unwrap(),
                &files.memory,
            )))?;
            memory_us = started.elapsed().as_micros() as u64;
            let vm_as = self
                .vm_as()
                .cloned()
                .ok_or(StartMicroVmError::GuestMemoryNotInitialized)?;
            self.init_vcpu_manager(
                vm_as.clone(),
                filters.get(VCPU_THREAD).cloned().unwrap_or_default(),
            )
            .map_err(StartMicroVmError::Vcpu)?;
            vcpu_manager_us = started.elapsed().as_micros() as u64;
            self.init_microvm_from_snapshot(events.epoll_manager(), vm_as, TimestampUs::default())?;
            devices_us = started.elapsed().as_micros() as u64;
            self.device_manager
                .arm_capture_restore(CaptureGeneration(generation))
                .map_err(|e| StartMicroVmError::RestoreMicroVm(e.to_string()))?;
            self.restore_held_state(&state)
                .map_err(|e| StartMicroVmError::RestoreMicroVm(e.to_string()))?;
            state_us = started.elapsed().as_micros() as u64;
            self.register_events(events)?;
            events_us = started.elapsed().as_micros() as u64;
            self.vcpu_manager()
                .map_err(StartMicroVmError::Vcpu)?
                .start_vcpus(
                    self.vm_config.vcpu_count,
                    filters.get(VMM_THREAD).cloned().unwrap_or_default(),
                    false,
                )
                .map_err(StartMicroVmError::Vcpu)?;
            Ok(())
        })();
        restored.map_err(terminal)?;
        let threads_us = started.elapsed().as_micros() as u64;
        let vcpu_acks = self
            .capture_cpu_manager(deadline)?
            .capture_pause(generation, deadline)
            .map_err(terminal)?;
        let cpu_held_us = started.elapsed().as_micros() as u64;
        let device_acks = self
            .device_manager
            .begin_capture(CaptureGeneration(generation), deadline)
            .map_err(terminal)?;
        let memory_layout = self.address_space.capture_layout().map_err(terminal)?;
        self.shared_info.write().unwrap().state = InstanceState::Paused;
        let report = CaptureReport {
            generation,
            vcpu_acks,
            device_acks,
            memory_layout,
        };
        self.capture_session.as_mut().unwrap().report = Some(report.clone());
        tracing::debug!(
            generation,
            decoded_us,
            memory_us,
            vcpu_manager_us,
            devices_us,
            state_us,
            events_us,
            threads_us,
            cpu_held_us,
            completed_us = started.elapsed().as_micros() as u64,
            "Dragonball LoadHeld worker timing (cumulative)"
        );
        Ok(report)
    }

    fn read_held_snapshot(
        &self,
        files: &SnapshotFiles,
    ) -> std::result::Result<MicrovmState, SnapshotError> {
        if !files.state.metadata()?.is_file() {
            return Err(SnapshotError::InvalidSnapshot(
                "held snapshot state must be a regular file".into(),
            ));
        }
        crate::address_space_manager::inspect_memory_backing(&files.memory)?;
        let mut file = files.state.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let value: serde_json::Value = serde_json::from_reader(BufReader::new(file))
            .map_err(crate::snapshot::PersistError::from)?;
        crate::snapshot::check_epoch(
            value
                .get("header")
                .and_then(|h| h.get("format_epoch"))
                .and_then(|e| e.as_u64())
                .unwrap_or(0),
            crate::snapshot::FORMAT_EPOCH,
        )?;
        if let Some(devices) = value.get("device_states").and_then(|v| v.as_object()) {
            if devices.iter().any(|(name, value)| {
                name != "block"
                    && name != "virtio_net"
                    && !(cfg!(feature = "virtio-balloon") && name == "balloon")
                    && !(cfg!(feature = "virtio-pmem") && name == "pmem")
                    && !(cfg!(feature = "virtio-fs") && name == "fs")
                    && !(cfg!(feature = "virtio-vsock") && name == "vsock")
                    && !value.is_null()
            }) {
                return Err(SnapshotError::InvalidSnapshot(
                    "snapshot contains an unsupported memory writer".into(),
                ));
            }
        }
        let state: MicrovmState =
            serde_json::from_value(value).map_err(crate::snapshot::PersistError::from)?;
        state.validate_for_restore(self.vm_config.vcpu_count)?;
        #[cfg(feature = "virtio-balloon")]
        {
            let saved = state
                .device_states
                .balloon
                .as_ref()
                .map(|state| state.devices.as_slice())
                .unwrap_or(&[]);
            let configured = &self.device_manager.balloon_manager.info_list;
            if saved.len() != configured.len() {
                return Err(SnapshotError::InvalidSnapshot(
                    "balloon device set mismatch".into(),
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for device in saved {
                let config = configured
                    .iter()
                    .find(|info| info.config.balloon_id == device.config.balloon_id)
                    .ok_or_else(|| {
                        SnapshotError::InvalidSnapshot("unknown balloon device".into())
                    })?;
                let crate::device_manager::persist::VirtioTransportState::Mmio(transport) =
                    &device.transport;
                if !seen.insert(&device.config.balloon_id)
                    || config.config.f_reporting != device.config.f_reporting
                    || config.config.f_deflate_on_oom != device.config.f_deflate_on_oom
                    || transport.queues.len() != if device.config.f_reporting { 3 } else { 2 }
                    || !transport.device_activated
                {
                    return Err(SnapshotError::InvalidSnapshot(
                        "unsupported balloon state or queue set".into(),
                    ));
                }
            }
        }
        #[cfg(feature = "virtio-fs")]
        {
            let saved = state
                .device_states
                .fs
                .as_ref()
                .map(|fs| fs.devices.as_slice())
                .unwrap_or(&[]);
            let manager = self.device_manager.fs_manager.lock().unwrap();
            if saved.len() != manager.info_list.len() {
                return Err(SnapshotError::InvalidSnapshot(
                    "filesystem device set mismatch".into(),
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for device in saved {
                let configured = manager
                    .info_list
                    .iter()
                    .find(|info| info.config.tag == device.config.tag)
                    .ok_or_else(|| {
                        SnapshotError::InvalidSnapshot("unknown filesystem device".into())
                    })?;
                let crate::device_manager::persist::VirtioTransportState::Mmio(transport) =
                    &device.transport;
                if !seen.insert(&device.config.tag)
                    || serde_json::to_value(&configured.config)
                        .map_err(crate::snapshot::PersistError::from)?
                        != serde_json::to_value(&device.config)
                            .map_err(crate::snapshot::PersistError::from)?
                    || transport.queues.len() != device.config.num_queues + 1
                    || !transport.device_activated
                {
                    return Err(SnapshotError::InvalidSnapshot(
                        "unsupported filesystem state or queue set".into(),
                    ));
                }
            }
        }
        #[cfg(feature = "virtio-vsock")]
        {
            let saved = state
                .device_states
                .vsock
                .as_ref()
                .map(|state| state.devices.as_slice())
                .unwrap_or(&[]);
            let configured = &self.device_manager.vsock_manager.info_list;
            if saved.len() != configured.len() {
                return Err(SnapshotError::InvalidSnapshot(
                    "vsock device set mismatch".into(),
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for device in saved {
                let config = configured
                    .iter()
                    .find(|info| info.config.id == device.config.id)
                    .ok_or_else(|| SnapshotError::InvalidSnapshot("unknown vsock device".into()))?;
                let crate::device_manager::persist::VirtioTransportState::Mmio(transport) =
                    &device.transport;
                if !seen.insert(&device.config.id)
                    || config.config.guest_cid != device.config.guest_cid
                    || config.config.queue_sizes() != device.config.queue_sizes()
                    || transport.queues.len() != dbs_virtio_devices::vsock::NUM_QUEUES
                    || !transport.device_activated
                {
                    return Err(SnapshotError::InvalidSnapshot(
                        "unsupported vsock state or queue set".into(),
                    ));
                }
            }
        }
        let saved_blocks = state
            .device_states
            .block
            .as_ref()
            .map(|v| v.devices.as_slice())
            .unwrap_or(&[]);
        let configured_blocks = self.device_manager.block_manager.iter().collect::<Vec<_>>();
        if saved_blocks.len() != configured_blocks.len() {
            return Err(SnapshotError::InvalidSnapshot(
                "block device set mismatch".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for saved in saved_blocks {
            let config = configured_blocks
                .iter()
                .find(|info| info.config.drive_id == saved.config.drive_id)
                .ok_or_else(|| SnapshotError::InvalidSnapshot("unknown block device ID".into()))?;
            let crate::device_manager::persist::VirtioTransportState::Mmio(transport) =
                &saved.transport;
            if !seen.insert(&saved.config.drive_id)
                || saved.config.device_type != config.config.device_type
                || saved.config.num_queues != config.config.num_queues
                || saved.config.queue_size != config.config.queue_size
                || saved.config.is_read_only != config.config.is_read_only
                || saved.config.is_volume_slot != config.config.is_volume_slot
                || (saved
                    .config
                    .backing_read_only
                    .unwrap_or(saved.config.is_read_only)
                    != config
                        .config
                        .backing_read_only
                        .unwrap_or(config.config.is_read_only)
                    && !self
                        .device_manager
                        .block_manager
                        .has_restore_slot_binding(&saved.config.drive_id))
                || saved.config.sparse != config.config.sparse
                || transport.queues.len() != config.config.num_queues
                || !transport.device_activated
            {
                return Err(SnapshotError::InvalidSnapshot(
                    "unsupported block state or queue set".into(),
                ));
            }
        }
        let saved_nets = state
            .device_states
            .virtio_net
            .as_ref()
            .map(|v| v.devices.as_slice())
            .unwrap_or(&[]);
        if saved_nets.len() != self.device_manager.net_manager.info_list.len() {
            return Err(SnapshotError::InvalidSnapshot(
                "network device set mismatch".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        use crate::config_manager::ConfigItem;
        for saved in saved_nets {
            let id = saved.config.id();
            let crate::device_manager::persist::VirtioTransportState::Mmio(transport) =
                &saved.transport;
            if !seen.insert(id)
                || !self
                    .device_manager
                    .net_manager
                    .info_list
                    .iter()
                    .any(|info| info.config.id() == id)
                || !matches!(
                    saved.config.backend,
                    crate::device_manager::net_dev_mgr::Backend::Virtio(_)
                )
                || transport.queues.len() != 2
                || !transport.device_activated
            {
                return Err(SnapshotError::InvalidSnapshot(
                    "unsupported network state or device set".into(),
                ));
            }
        }
        #[cfg(feature = "virtio-pmem")]
        self.device_manager
            .pmem_manager
            .validate_snapshot(&state.device_states.pmem.clone().unwrap_or_default())?;
        let requirements = state.capture_cpu.as_ref().ok_or_else(|| {
            SnapshotError::InvalidSnapshot("legacy snapshot lacks held CPU requirements".into())
        })?;
        let cpuid = host_cpu_requirements(&self.kvm)?;
        let msrs = self.kvm.supported_msrs(0).map_err(SnapshotError::Kvm)?;
        if requirements.cpuid.as_slice() != cpuid.as_slice()
            || requirements.msr_indices != msrs.as_slice()
        {
            let difference = requirements
                .cpuid
                .as_slice()
                .iter()
                .zip(cpuid.as_slice())
                .find(|(left, right)| left != right);
            return Err(SnapshotError::InvalidSnapshot(format!(
                "host CPU/MSR requirements mismatch: {difference:?}"
            )));
        }
        if self.vm_fd.check_extension_int(kvm_ioctls::Cap::Xsave2)
            > std::mem::size_of::<kvm_bindings::kvm_xsave>() as i32
        {
            return Err(SnapshotError::InvalidSnapshot(
                "extended XSAVE buffers are not qualified".into(),
            ));
        }
        let xsave_features = cpuid
            .as_slice()
            .iter()
            .find(|entry| entry.function == 0x0d && entry.index == 0)
            .map(|entry| u64::from(entry.eax) | (u64::from(entry.edx) << 32))
            .unwrap_or(3);
        for cpu in &state.vcpu_states {
            let mut seen = std::collections::HashSet::new();
            for entry in cpu.msrs.iter().flat_map(|chunk| chunk.as_slice()) {
                if !requirements.msr_indices.contains(&entry.index) || !seen.insert(entry.index) {
                    return Err(SnapshotError::InvalidSnapshot(
                        "unknown or duplicate saved MSR".into(),
                    ));
                }
            }
            let xstate =
                u64::from(cpu.xsave.region[128]) | (u64::from(cpu.xsave.region[129]) << 32);
            let xcomp = u64::from(cpu.xsave.region[130]) | (u64::from(cpu.xsave.region[131]) << 32);
            if xstate & !xsave_features != 0
                || xcomp != 0
                || cpu.xcrs.nr_xcrs as usize > cpu.xcrs.xcrs.len()
            {
                return Err(SnapshotError::InvalidSnapshot(
                    "unsupported XSAVE layout".into(),
                ));
            }
            let mut enabled = xstate;
            for xcr in &cpu.xcrs.xcrs[..cpu.xcrs.nr_xcrs as usize] {
                if xcr.xcr != 0 || xcr.value & !xsave_features != 0 {
                    return Err(SnapshotError::InvalidSnapshot(
                        "unsupported XCR state".into(),
                    ));
                }
                enabled |= xcr.value;
            }
            for entry in cpuid
                .as_slice()
                .iter()
                .filter(|entry| entry.function == 0x0d && (2..64).contains(&entry.index))
            {
                if enabled & (1u64 << entry.index) != 0
                    && u64::from(entry.ebx) + u64::from(entry.eax) > 4096
                {
                    return Err(SnapshotError::InvalidSnapshot(
                        "XSAVE component exceeds the qualified buffer".into(),
                    ));
                }
            }
        }
        Ok(state)
    }

    fn restore_held_state(
        &mut self,
        state: &MicrovmState,
    ) -> std::result::Result<(), SnapshotError> {
        // RAM was fully validated and privately mapped before creating consumers.
        let kvm = state.vm_kvm_state.as_ref().unwrap();
        self.vm_fd.set_pit2(&kvm.pit).map_err(SnapshotError::Kvm)?;
        self.vm_fd
            .set_clock(&kvm.clock)
            .map_err(SnapshotError::Kvm)?;
        self.vm_fd
            .set_irqchip(&kvm.pic_master)
            .map_err(SnapshotError::Kvm)?;
        self.vm_fd
            .set_irqchip(&kvm.pic_slave)
            .map_err(SnapshotError::Kvm)?;
        self.vm_fd
            .set_irqchip(&kvm.ioapic)
            .map_err(SnapshotError::Kvm)?;
        // KVM validates CPUID/MSR/XSAVE before any device is activated or CPU thread runs.
        self.vcpu_manager()?.restore_state(&state.vcpu_states, ())?;
        #[cfg(feature = "virtio-pmem")]
        if let Some(pmem) = &state.device_states.pmem {
            self.device_manager.pmem_manager.restore_state(pmem, ())?;
        }
        if let Some(block) = &state.device_states.block {
            self.device_manager.block_manager.restore_state(block, ())?;
        }
        if let Some(net) = &state.device_states.virtio_net {
            self.device_manager.net_manager.restore_state(net, ())?;
        }
        #[cfg(feature = "virtio-fs")]
        if let Some(fs) = &state.device_states.fs {
            self.device_manager
                .fs_manager
                .lock()
                .unwrap()
                .restore_state(fs, ())?;
        }
        #[cfg(feature = "virtio-vsock")]
        if let Some(vsock) = &state.device_states.vsock {
            self.device_manager
                .vsock_manager
                .restore_state(vsock, true)?;
        }
        #[cfg(feature = "virtio-balloon")]
        if let Some(balloon) = &state.device_states.balloon {
            self.device_manager
                .balloon_manager
                .restore_state(balloon, ())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::capture::SnapshotFiles;
    use crate::vcpu::RealVcpuExecution;
    use dbs_snapshot::Persist;
    use std::convert::TryInto;
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;
    use std::time::{Duration, Instant};
    use vm_memory::GuestMemory;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn held_snapshot_state_reads_are_batched() {
        // Track this thread only: other parallel tests must not affect the budget.
        fn read_calls() -> u64 {
            std::fs::read_to_string("/proc/thread-self/io")
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("syscr: "))
                .unwrap()
                .parse()
                .unwrap()
        }
        let vm = super::super::tests::create_vm_instance();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        memory.as_file().set_len(16 << 20).unwrap();
        // A complete JSON document with an invalid snapshot header must still
        // be rejected, without a syscall for every byte of valid whitespace.
        let mut json = vec![b' '; 64 * 1024];
        json.extend_from_slice(b"{}");
        state.as_file().write_all(&json).unwrap();
        let input = files(&state, &memory);
        let before = read_calls();
        let result = vm.read_held_snapshot(&input);
        let calls = read_calls() - before;
        eprintln!(
            "held snapshot state: {} bytes, {} read calls",
            json.len(),
            calls
        );
        assert!(result.is_err(), "invalid snapshot header must be rejected");
        assert!(
            calls < 64,
            "state parser issued {} reads for {} bytes",
            calls,
            json.len()
        );
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(3)
    }

    fn files(state: &TempFile, memory: &TempFile) -> SnapshotFiles {
        SnapshotFiles::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(state.as_path())
                .unwrap(),
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(memory.as_path())
                .unwrap(),
        )
    }

    fn paused_counter_vm() -> (Vm, RealVcpuExecution) {
        paused_counter_vm_with_disk(None)
    }

    #[cfg(feature = "virtio-vsock")]
    fn configure_vsock(vm: &mut Vm) {
        use crate::config_manager::DeviceConfigInfo;
        use crate::device_manager::vsock_dev_mgr::VsockDeviceConfigInfo;
        vm.device_manager
            .vsock_manager
            .info_list
            .push(DeviceConfigInfo::new(VsockDeviceConfigInfo {
                id: "agent".into(),
                guest_cid: 52,
                use_shared_irq: Some(false),
                use_generic_irq: Some(false),
                ..Default::default()
            }));
    }

    #[cfg(feature = "virtio-vsock")]
    #[test]
    fn held_vsock_restore_preserves_queues_until_reset_and_ack() {
        use crate::device_manager::{DbsMmioV2Device, DeviceOpContext};
        use dbs_virtio_devices::persist::VirtioQueueState;
        let (mut source, _real) = paused_counter_vm();
        configure_vsock(&mut source);
        let mut context = DeviceOpContext::new(
            Some(source.epoll_manager.clone()),
            &source.device_manager,
            source.vm_as().cloned(),
            source.vm_address_space().cloned(),
            false,
            Some(source.vm_config.clone()),
            source.shared_info.clone(),
        );
        source
            .device_manager
            .vsock_manager
            .attach_devices(&mut context)
            .unwrap();
        let device = source.device_manager.vsock_manager.info_list[0]
            .device
            .as_ref()
            .unwrap()
            .clone();
        let mmio = device.as_any().downcast_ref::<DbsMmioV2Device>().unwrap();
        mmio.state().get_inner_device_mut().set_acked_features(1, 1);
        let memory = source.address_space.vm_memory().unwrap();
        let mut transport = mmio.save_state();
        for (index, queue) in transport.queues.iter_mut().enumerate() {
            let base = 0x4000 + index as u64 * 0x1000;
            queue.queue = VirtioQueueState {
                max_size: 256,
                size: 16,
                ready: true,
                desc_table: base,
                avail_ring: base + 0x200,
                used_ring: base + 0x300,
                ..Default::default()
            };
        }
        // Post the event buffer that the guest driver uses for TRANSPORT_RESET.
        memory.write_obj(0x8000u64, GuestAddress(0x6000)).unwrap();
        memory.write_obj(4u32, GuestAddress(0x6008)).unwrap();
        memory.write_obj(2u16, GuestAddress(0x600c)).unwrap();
        memory.write_obj(1u16, GuestAddress(0x6202)).unwrap();
        transport.driver_status = 0xf;
        transport.device_activated = true;
        mmio.restore_state(&transport).unwrap();
        let config = source.vm_config.clone();
        let state_file = TempFile::new().unwrap();
        let ram_file = TempFile::new().unwrap();
        let input = files(&state_file, &ram_file);
        let capture = source.begin_capture(1, deadline());
        if capture.is_err() {
            source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        }
        let capture = capture.unwrap();
        assert_eq!(capture.device_acks[0].device_id, "vsock:agent");
        source.export_held_snapshot(1, deadline(), &input).unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        drop(memory);
        drop(source);

        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll.clone()).unwrap();
        let mut vmm = vmm.lock().unwrap();
        let target = vmm.get_vm_mut().unwrap();
        let real = RealVcpuExecution::new(target.vm_fd.clone());
        target.set_vm_config(config);
        configure_vsock(target);
        target
            .load_snapshot_held(&mut events, Default::default(), &input, 1, deadline())
            .unwrap();
        epoll.handle_events(0).unwrap();
        let ram = target.address_space.vm_memory().unwrap();
        assert_eq!(real.run_count(), 0);
        assert_eq!(ram.read_obj::<u16>(GuestAddress(0x6302)).unwrap(), 0);
        target.end_capture(1, deadline(), false).unwrap();
        epoll.handle_events(0).unwrap();
        assert!(!target
            .device_manager
            .vsock_manager
            .finalize_restore()
            .unwrap());
        assert_eq!(ram.read_obj::<u16>(GuestAddress(0x6302)).unwrap(), 1);
        // Model the guest driver reposting an event buffer after handling reset.
        ram.write_obj(2u16, GuestAddress(0x6202)).unwrap();
        assert!(target
            .device_manager
            .vsock_manager
            .finalize_restore()
            .unwrap());
        target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    }

    #[cfg(feature = "virtio-pmem")]
    fn configure_pmem(vm: &mut Vm, path: &std::path::Path) {
        use crate::config_manager::DeviceConfigInfo;
        use crate::device_manager::pmem_dev_mgr::PmemDeviceConfigInfo;
        vm.device_manager
            .pmem_manager
            .info_list
            .push(DeviceConfigInfo::new(PmemDeviceConfigInfo {
                id: "guest-image".into(),
                path: path.to_str().unwrap().into(),
                read_only: true,
                use_shared_irq: Some(false),
                use_generic_irq: Some(false),
                ..Default::default()
            }));
    }

    #[cfg(feature = "virtio-pmem")]
    #[test]
    fn held_pmem_restore_keeps_image_outside_ram() {
        use crate::device_manager::{DbsMmioV2Device, DeviceOpContext};
        use dbs_virtio_devices::persist::VirtioQueueState;
        let image = TempFile::new().unwrap();
        image.as_file().set_len(2 << 20).unwrap();
        image
            .as_file()
            .write_all_at(b"immutable-system-image", 0)
            .unwrap();
        let image_metadata = image.as_file().metadata().unwrap();
        let (mut source, _real) = paused_counter_vm();
        configure_pmem(&mut source, image.as_path());
        let mut context = DeviceOpContext::new(
            Some(source.epoll_manager.clone()),
            &source.device_manager,
            source.vm_as().cloned(),
            source.vm_address_space().cloned(),
            false,
            Some(source.vm_config.clone()),
            source.shared_info.clone(),
        );
        source
            .device_manager
            .pmem_manager
            .attach_devices(&mut context)
            .unwrap();
        let device = source.device_manager.pmem_manager.info_list[0]
            .device
            .as_ref()
            .unwrap()
            .clone();
        let mmio = device.as_any().downcast_ref::<DbsMmioV2Device>().unwrap();
        mmio.state().get_inner_device_mut().set_acked_features(1, 1);
        let mut transport = mmio.save_state();
        transport.queues[0].queue = VirtioQueueState {
            max_size: 256,
            size: 16,
            ready: true,
            next_avail: 0,
            next_used: 0,
            desc_table: 0x4000,
            avail_ring: 0x4200,
            used_ring: 0x4300,
            ..Default::default()
        };
        transport.driver_status = 0xf;
        transport.device_activated = true;
        mmio.restore_state(&transport).unwrap();
        let config = source.vm_config.clone();
        let state_file = TempFile::new().unwrap();
        let ram_file = TempFile::new().unwrap();
        let input = files(&state_file, &ram_file);
        let report = source.begin_capture(1, deadline()).unwrap();
        assert_eq!(report.memory_layout.total_bytes, 16 << 20);
        assert_eq!(report.device_acks[0].device_id, "pmem:guest-image");
        assert!(source
            .export_held_snapshot(
                1,
                deadline(),
                &SnapshotFiles::new(
                    image.as_file().try_clone().unwrap(),
                    input.memory.try_clone().unwrap()
                )
            )
            .is_err());
        source.export_held_snapshot(1, deadline(), &input).unwrap();
        assert_eq!(input.memory.metadata().unwrap().len(), 16 << 20);
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        drop(source);
        for index in 0..3 {
            let epoll = EpollManager::default();
            let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
                epoll.clone(),
            )));
            let mut events = EventManager::new(&vmm, epoll.clone()).unwrap();
            let mut vmm = vmm.lock().unwrap();
            let target = vmm.get_vm_mut().unwrap();
            let _real = RealVcpuExecution::new(target.vm_fd.clone());
            target.set_vm_config(config.clone());
            // Rebind the same inode through a different path, as the runner does with FDs.
            let replacement = TempFile::new().unwrap();
            std::fs::copy(image.as_path(), replacement.as_path()).unwrap();
            let mut input = files(&state_file, &ram_file);
            let alias = if index == 1 {
                let live = replacement.as_file().metadata().unwrap();
                input
                    .pmem_bindings
                    .push(crate::device_manager::pmem_dev_mgr::RestorePmemBinding {
                        id: "guest-image".into(),
                        saved_backing: (
                            image_metadata.dev(),
                            image_metadata.ino(),
                            image_metadata.len(),
                        ),
                        current_backing: (live.dev(), live.ino(), live.len()),
                    });
                replacement.as_file().try_clone().unwrap()
            } else {
                image.as_file().try_clone().unwrap()
            };
            let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", alias.as_raw_fd()));
            configure_pmem(target, &path);
            if index == 1 {
                let invalid = TempFile::new().unwrap();
                invalid.as_file().write_all_at(b"{}", 0).unwrap();
                let mut rejected = files(&invalid, &ram_file);
                rejected.pmem_bindings = input.pmem_bindings.clone();
                assert!(target
                    .load_snapshot_held(&mut events, Default::default(), &rejected, 1, deadline())
                    .is_err());
            }
            target
                .load_snapshot_held(&mut events, Default::default(), &input, 1, deadline())
                .unwrap();
            let device = target.device_manager.pmem_manager.info_list[0]
                .device
                .as_ref()
                .unwrap();
            let restored = device
                .as_any()
                .downcast_ref::<DbsMmioV2Device>()
                .unwrap()
                .save_state();
            assert_eq!(restored.queues, transport.queues);
            assert!(restored.device_activated);
            assert_eq!(
                target.address_space.capture_layout().unwrap().total_bytes,
                16 << 20
            );
            target.end_capture(1, deadline(), false).unwrap();
            target.begin_capture(2, deadline()).unwrap();
            let next_state = TempFile::new().unwrap();
            let next_ram = TempFile::new().unwrap();
            target
                .export_held_snapshot(2, deadline(), &files(&next_state, &next_ram))
                .unwrap();
            assert_eq!(next_ram.as_file().metadata().unwrap().len(), 16 << 20);
            target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        }
        assert_eq!(
            image.as_file().metadata().unwrap().blocks(),
            image_metadata.blocks()
        );
        let mut marker = [0; 22];
        image.as_file().read_exact_at(&mut marker, 0).unwrap();
        assert_eq!(&marker, b"immutable-system-image");
    }

    #[cfg(feature = "virtio-balloon")]
    fn configure_balloon(vm: &mut Vm) {
        use crate::config_manager::DeviceConfigInfo;
        use crate::device_manager::balloon_dev_mgr::BalloonDeviceConfigInfo;
        vm.device_manager
            .balloon_manager
            .info_list
            .push(DeviceConfigInfo::new(BalloonDeviceConfigInfo {
                balloon_id: "memory".into(),
                size_mib: 2,
                use_shared_irq: Some(false),
                use_generic_irq: Some(false),
                f_deflate_on_oom: true,
                f_reporting: true,
            }));
    }

    #[cfg(feature = "virtio-balloon")]
    #[test]
    fn m2_balloon_restore_preserves_queues_and_progress() {
        use crate::device_manager::{DbsMmioV2Device, DeviceOpContext};
        use dbs_virtio_devices::persist::VirtioQueueState;
        let (mut source, _real) = paused_counter_vm();
        configure_balloon(&mut source);
        let mut context = DeviceOpContext::new(
            Some(source.epoll_manager.clone()),
            &source.device_manager,
            source.vm_as().cloned(),
            source.vm_address_space().cloned(),
            false,
            Some(source.vm_config.clone()),
            source.shared_info.clone(),
        );
        source
            .device_manager
            .balloon_manager
            .attach_devices(&mut context)
            .unwrap();
        let device = source.device_manager.balloon_manager.info_list[0]
            .device
            .as_ref()
            .unwrap()
            .clone();
        let mmio = device.as_any().downcast_ref::<DbsMmioV2Device>().unwrap();
        {
            let mut guard = mmio.state();
            let inner = guard.get_inner_device_mut();
            inner.set_acked_features(0, (1 << 2) | (1 << 5));
            inner.set_acked_features(1, 1);
            inner.write_config(0, &512u32.to_le_bytes()).unwrap();
            inner.write_config(4, &123u32.to_le_bytes()).unwrap();
        }
        let memory = source.address_space.vm_memory().unwrap();
        memory
            .write_slice(&[0x51; 8192], GuestAddress(0x9000))
            .unwrap();
        // The real CPU copies a reclaimed-then-rewritten page through the same KVM slot.
        memory
            .write_slice(
                &[
                    0xff, 0x06, 0x00, 0x20, 0xa0, 0x00, 0xa0, 0xa2, 0x00, 0xb0, 0xeb, 0xf4,
                ],
                GuestAddress(0x1000),
            )
            .unwrap();
        memory.write_obj(9u32, GuestAddress(0x8000)).unwrap();
        let mut transport = mmio.save_state();
        for (index, queue) in transport.queues.iter_mut().enumerate() {
            let base = 0x4000 + index as u64 * 0x1000;
            queue.queue = VirtioQueueState {
                max_size: 128,
                size: 16,
                ready: true,
                next_avail: 7,
                next_used: 7,
                desc_table: base,
                avail_ring: base + 0x200,
                used_ring: base + 0x300,
                ..Default::default()
            };
            memory
                .write_obj(
                    if index == 2 { 0xa000u64 } else { 0x8000 },
                    GuestAddress(base),
                )
                .unwrap();
            memory
                .write_obj(if index == 2 { 4096u32 } else { 4 }, GuestAddress(base + 8))
                .unwrap();
            memory
                .write_obj(if index == 2 { 2u16 } else { 0 }, GuestAddress(base + 12))
                .unwrap();
            memory.write_obj(8u16, GuestAddress(base + 0x202)).unwrap();
            memory
                .write_obj(0u16, GuestAddress(base + 0x204 + 7 * 2))
                .unwrap();
            memory.write_obj(7u16, GuestAddress(base + 0x302)).unwrap();
        }
        transport.driver_status = 0xf;
        transport.device_activated = true;
        mmio.restore_state(&transport).unwrap();
        let config = source.vm_config.clone();
        let state_file = TempFile::new().unwrap();
        let ram_file = TempFile::new().unwrap();
        let input = files(&state_file, &ram_file);
        let report = source.begin_capture(1, deadline());
        if report.is_err() {
            source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        }
        let report = report.unwrap();
        assert_eq!(report.device_acks.len(), 1);
        assert_eq!(report.device_acks[0].device_id, "balloon:memory");
        source.export_held_snapshot(1, deadline(), &input).unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        drop(memory);
        drop(source);
        let (mut legacy, _legacy_real) = paused_counter_vm();
        let legacy_result = legacy.restore_microvm(state_file.as_path(), ram_file.as_path(), false);
        legacy.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert!(
            matches!(legacy_result, Err(SnapshotError::InvalidSnapshot(message))
            if message.contains("held restore"))
        );
        let mut lower = vec![0; 16 << 20];
        input.memory.read_exact_at(&mut lower, 0).unwrap();
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll.clone()).unwrap();
        let mut vmm = vmm.lock().unwrap();
        let target = vmm.get_vm_mut().unwrap();
        let real = RealVcpuExecution::new(target.vm_fd.clone());
        target.set_vm_config(config);
        configure_balloon(target);
        target
            .load_snapshot_held(&mut events, Default::default(), &input, 1, deadline())
            .unwrap();
        let restored = target.device_manager.balloon_manager.info_list[0]
            .device
            .as_ref()
            .unwrap()
            .clone();
        let mmio = restored.as_any().downcast_ref::<DbsMmioV2Device>().unwrap();
        assert_eq!(mmio.save_state().queues, transport.queues);
        assert!(mmio.save_state().device_activated);
        let mut config_bytes = [0u8; 8];
        mmio.state()
            .get_inner_device_mut()
            .read_config(0, &mut config_bytes)
            .unwrap();
        assert_eq!(&config_bytes[..4], &512u32.to_le_bytes());
        assert_eq!(&config_bytes[4..], &123u32.to_le_bytes());
        epoll.handle_events(0).unwrap();
        let ram = target.address_space.vm_memory().unwrap();
        assert_eq!(ram.read_obj::<u16>(GuestAddress(0x6302)).unwrap(), 7);
        assert_eq!(ram.read_obj::<u8>(GuestAddress(0xa000)).unwrap(), 0x51);
        assert_eq!(real.run_count(), 0);
        target.end_capture(1, deadline(), false).unwrap();
        epoll.handle_events(0).unwrap();
        for index in 0..3 {
            assert_eq!(
                ram.read_obj::<u16>(GuestAddress(0x4302 + index * 0x1000))
                    .unwrap(),
                8
            );
        }
        assert_eq!(ram.read_obj::<u8>(GuestAddress(0x9000)).unwrap(), 0);
        assert_eq!(ram.read_obj::<u8>(GuestAddress(0xa000)).unwrap(), 0);
        target.begin_capture(2, deadline()).unwrap();
        let zero = target.export_held_memory_map(2, deadline()).unwrap();
        assert!(
            zero.changed_ranges
                .iter()
                .map(|range| range.length)
                .sum::<u64>()
                < 16 << 20
        );
        for page in [0x4000, 0x5000, 0x6000, 0x9000, 0xa000] {
            assert!(zero.changed_ranges.iter().any(
                |range| range.image_offset <= page && range.image_offset + range.length > page
            ));
        }
        assert!(zero.zero_ranges.iter().any(
            |range| range.image_offset <= 0xa000 && range.image_offset + range.length > 0xa000
        ));
        target.release_held_memory_map(2).unwrap();
        target.end_capture(2, deadline(), false).unwrap();
        ram.write_obj(0x93u8, GuestAddress(0xa000)).unwrap();
        target.begin_capture(3, deadline()).unwrap();
        let rewritten = target.export_held_memory_map(3, deadline()).unwrap();
        assert!(rewritten.changed_ranges.iter().any(
            |range| range.image_offset <= 0xa000 && range.image_offset + range.length > 0xa000
        ));
        assert!(!rewritten.zero_ranges.iter().any(
            |range| range.image_offset <= 0xa000 && range.image_offset + range.length > 0xa000
        ));
        let mut after = vec![0; lower.len()];
        input.memory.read_exact_at(&mut after, 0).unwrap();
        assert_eq!(after, lower);
        target.release_held_memory_map(3).unwrap();
        target.end_capture(3, deadline(), true).unwrap();
        let limit = deadline();
        while ram.read_obj::<u8>(GuestAddress(0xb000)).unwrap() != 0x93 && Instant::now() < limit {
            std::thread::yield_now();
        }
        target.begin_capture(4, deadline()).unwrap();
        assert!(real.run_count() > 0);
        assert_eq!(ram.read_obj::<u8>(GuestAddress(0xa000)).unwrap(), 0x93);
        assert_eq!(ram.read_obj::<u8>(GuestAddress(0xb000)).unwrap(), 0x93);
        let map = target.export_held_memory_map(4, deadline()).unwrap();
        let mut rebuilt = lower.clone();
        for range in &map.changed_ranges {
            ram.read_slice(
                &mut rebuilt
                    [range.image_offset as usize..(range.image_offset + range.length) as usize],
                GuestAddress(range.image_offset),
            )
            .unwrap();
        }
        let full_state = TempFile::new().unwrap();
        let full_ram = TempFile::new().unwrap();
        target
            .export_held_snapshot(4, deadline(), &files(&full_state, &full_ram))
            .unwrap();
        full_ram.as_file().read_exact_at(&mut after, 0).unwrap();
        assert_eq!(
            rebuilt, after,
            "balloon + CPU delta must match the held full export"
        );
        target.release_held_memory_map(4).unwrap();
        target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    }

    #[test]
    fn held_snapshot_preserves_cold_memory_sparsity() {
        let (mut vm, real) = paused_counter_vm();
        let ram = vm.address_space.vm_memory().unwrap();
        vm.begin_capture(1, deadline()).unwrap();
        vm.end_capture(1, deadline(), true).unwrap();
        let limit = deadline();
        while ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap() == 0 && Instant::now() < limit {
            std::thread::yield_now();
        }
        vm.begin_capture(2, deadline()).unwrap();
        let counter = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        let source_blocks: u64 = ram
            .iter()
            .map(|region| {
                region
                    .file_offset()
                    .unwrap()
                    .file()
                    .metadata()
                    .unwrap()
                    .blocks()
            })
            .sum();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        // Reused outputs must lose old bytes, including a trailing allocated page.
        memory
            .as_file()
            .write_all_at(&[0xa5; 4096], (16 << 20) - 4096)
            .unwrap();
        let result = vm.export_held_snapshot(2, deadline(), &files(&state, &memory));
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        result.unwrap();
        assert!(real.run_count() > 0);
        assert_ne!(counter, 0);
        let output = memory.as_file().metadata().unwrap();
        assert_eq!(output.len(), 16 << 20);
        eprintln!(
            "cold RAM: logical={} allocated={} source_before={}",
            output.len(),
            output.blocks() * 512,
            source_blocks * 512
        );
        assert!(
            output.blocks() * 512 < output.len() / 2,
            "snapshot must preserve RAM holes"
        );
        let after_blocks: u64 = ram
            .iter()
            .map(|region| {
                region
                    .file_offset()
                    .unwrap()
                    .file()
                    .metadata()
                    .unwrap()
                    .blocks()
            })
            .sum();
        eprintln!("cold RAM: source_after={}", after_blocks * 512);
        assert_eq!(
            after_blocks, source_blocks,
            "export must not allocate untouched shmem pages"
        );
        let mut saved = [0; 2];
        memory.as_file().read_exact_at(&mut saved, 0x2000).unwrap();
        assert_eq!(u16::from_le_bytes(saved), counter);
        let mut tail = [1; 4096];
        memory
            .as_file()
            .read_exact_at(&mut tail, (16 << 20) - 4096)
            .unwrap();
        assert_eq!(tail, [0; 4096]);
    }

    #[test]
    #[cfg(feature = "virtio-balloon")]
    fn held_snapshot_preserves_cold_reclaimed_pages() {
        use crate::address_space_manager::PrivateMemoryReclaimer;
        let (mut vm, real) = paused_counter_vm();
        let ram = vm.address_space.vm_memory().unwrap();
        let region = ram.iter().next().unwrap();
        assert_ne!(region.flags() & libc::MAP_SHARED, 0);
        let backing = region.file_offset().unwrap().file();
        // Force real holes even on tmpfs hosts which allocate larger folios.
        // SAFETY: these complete pages are unused by the paused test guest.
        assert_eq!(
            unsafe {
                libc::fallocate(
                    backing.as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    0x6000,
                    8192,
                )
            },
            0
        );
        let reclaimer = PrivateMemoryReclaimer::new(
            vm.vm_as().cloned().unwrap(),
            vm.address_space.address_space().cloned().unwrap(),
        );
        ram.write_slice(&[0xa5; 8192], GuestAddress(0x6000))
            .unwrap();
        let allocated = backing.metadata().unwrap().blocks();
        reclaimer.reclaim_private_range(0x6000, 8192).unwrap();
        assert!(
            backing.metadata().unwrap().blocks() < allocated,
            "cold reporting must release shmem blocks"
        );
        // The real CPU writes the reclaimed page through the original slot.
        ram.write_slice(&[0xff, 0x06, 0x00, 0x60, 0xeb, 0xfa], GuestAddress(0x1000))
            .unwrap();
        vm.begin_capture(1, deadline()).unwrap();
        vm.end_capture(1, deadline(), true).unwrap();
        let limit = deadline();
        while ram.read_obj::<u16>(GuestAddress(0x6000)).unwrap() == 0 && Instant::now() < limit {
            std::thread::yield_now();
        }
        vm.begin_capture(2, deadline()).unwrap();
        let counter = ram.read_obj::<u16>(GuestAddress(0x6000)).unwrap();
        ram.write_obj(0x93u8, GuestAddress(0x7000)).unwrap();
        let before = backing.metadata().unwrap().blocks();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let result = vm.export_held_snapshot(2, deadline(), &files(&state, &memory));
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        result.unwrap();
        assert!(real.run_count() > 0);
        assert_ne!(counter, 0);
        let mut saved = [0; 2];
        memory.as_file().read_exact_at(&mut saved, 0x6000).unwrap();
        assert_eq!(
            u16::from_le_bytes(saved),
            counter,
            "CPU writes to cold reclaimed RAM must survive"
        );
        memory
            .as_file()
            .read_exact_at(&mut saved[..1], 0x7000)
            .unwrap();
        assert_eq!(
            saved[0], 0x93,
            "software writes to cold reclaimed RAM must survive"
        );
        assert_eq!(backing.metadata().unwrap().blocks(), before);
        assert_eq!(memory.as_file().metadata().unwrap().len(), 16 << 20);
        assert!(memory.as_file().metadata().unwrap().blocks() * 512 < 1 << 20);
    }

    #[test]
    fn held_snapshot_rejects_append_memory_output() {
        let (mut vm, _real) = paused_counter_vm();
        vm.begin_capture(1, deadline()).unwrap();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        state.as_file().write_all_at(b"state sentinel", 0).unwrap();
        memory
            .as_file()
            .write_all_at(b"memory sentinel", 0)
            .unwrap();
        let mut output = files(&state, &memory);
        output.memory = Arc::new(
            OpenOptions::new()
                .read(true)
                .append(true)
                .open(memory.as_path())
                .unwrap(),
        );
        let result = vm.export_held_snapshot(1, deadline(), &output);
        let held = vm.end_capture(1, deadline(), false);
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert!(result.is_err(), "append mode cannot honor packed offsets");
        held.unwrap();
        assert_eq!(std::fs::read(state.as_path()).unwrap(), b"state sentinel");
        assert_eq!(std::fs::read(memory.as_path()).unwrap(), b"memory sentinel");
    }

    #[test]
    fn held_snapshot_rejects_legacy_restore_without_mutating_outputs() {
        let (mut source, _real) = paused_counter_vm();
        source
            .address_space
            .vm_memory()
            .unwrap()
            .write_obj(0x73u8, GuestAddress(8 << 20))
            .unwrap();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        source.begin_capture(1, deadline()).unwrap();
        source
            .export_held_snapshot(1, deadline(), &files(&state, &memory))
            .unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        let config = source.vm_config.clone();
        drop(source);
        let mut target = super::super::tests::create_vm_instance();
        target.set_vm_config(config);
        target.init_guest_memory().unwrap();
        let vm_as = target.vm_as().cloned().unwrap();
        target
            .init_vcpu_manager(vm_as.clone(), Default::default())
            .unwrap();
        target
            .init_microvm_from_snapshot(target.epoll_manager.clone(), vm_as, TimestampUs::default())
            .unwrap();
        target
            .restore_microvm(state.as_path(), memory.as_path(), false)
            .unwrap();
        target
            .vcpu_manager()
            .unwrap()
            .start_vcpus(1, Default::default(), false)
            .unwrap();
        target.set_instance_state(InstanceState::Paused);
        target.begin_capture(1, deadline()).unwrap();
        let output_state = TempFile::new().unwrap();
        let output_memory = TempFile::new().unwrap();
        output_state
            .as_file()
            .write_all_at(b"state sentinel", 0)
            .unwrap();
        output_memory
            .as_file()
            .write_all_at(b"memory sentinel", 0)
            .unwrap();
        let ancestor = std::fs::read(memory.as_path()).unwrap();
        for output in [
            files(&output_state, &output_memory),
            files(&memory, &output_memory),
            files(&output_state, &memory),
        ] {
            if target.export_held_snapshot(1, deadline(), &output).is_ok() {
                target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
                panic!("legacy mapping has no current backing proof");
            }
            assert_eq!(std::fs::read(memory.as_path()).unwrap(), ancestor);
            assert_eq!(
                std::fs::read(output_state.as_path()).unwrap(),
                b"state sentinel"
            );
            assert_eq!(
                std::fs::read(output_memory.as_path()).unwrap(),
                b"memory sentinel"
            );
        }
        target.end_capture(1, deadline(), false).unwrap();
        target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    }

    #[test]
    fn held_snapshot_preserves_sparse_cow_across_restores() {
        let (mut source, _real) = paused_counter_vm();
        let ram = source.address_space.vm_memory().unwrap();
        ram.write_slice(&[0x51; 4096], GuestAddress(0x5000))
            .unwrap();
        ram.write_slice(&[0x72; 4096], GuestAddress(8 << 20))
            .unwrap();
        let config = source.vm_config.clone();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let mut input = files(&state, &memory);
        source.begin_capture(1, deadline()).unwrap();
        source.export_held_snapshot(1, deadline(), &input).unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        drop(ram);
        drop(source);
        let mut expected = vec![0; 16 << 20];
        input.memory.read_exact_at(&mut expected, 0).unwrap();
        for cycle in 1..=3 {
            let ancestor = expected.clone();
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
            // No read of the unchanged nonzero page at 8 MiB before export.
            let host = ram.get_host_address(GuestAddress(8 << 20)).unwrap() as u64;
            let mut pte = [0; 8];
            File::open("/proc/self/pagemap")
                .unwrap()
                .read_exact_at(&mut pte, host / 4096 * 8)
                .unwrap();
            assert_eq!(
                u64::from_le_bytes(pte) & (1 << 63),
                0,
                "base page must be nonresident in the new mapping"
            );
            let previous = u16::from_le_bytes(expected[0x2000..0x2002].try_into().unwrap());
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
            // Software/DMA writes include both an ancestor page cleared to zero
            // and a private nonzero page whose ancestor is a hole.
            ram.write_slice(&[0; 4096], GuestAddress(0x5000)).unwrap();
            ram.write_slice(&[cycle; 4096], GuestAddress(6 << 20))
                .unwrap();
            expected[0x2000..0x2002].copy_from_slice(&counter.to_le_bytes());
            expected[0x5000..0x6000].fill(0);
            expected[6 << 20..(6 << 20) + 4096].fill(cycle);
            let output_state = TempFile::new().unwrap();
            let output_memory = TempFile::new().unwrap();
            let mut readonly = files(&output_state, &output_memory);
            readonly.memory = Arc::new(File::open(output_memory.as_path()).unwrap());
            assert!(target
                .export_held_snapshot(2, deadline(), &readonly)
                .is_err());
            target.end_capture(2, deadline(), false).unwrap();
            target.begin_capture(3, deadline()).unwrap();
            target
                .export_held_memory_map_without_zero_scan(3, deadline())
                .unwrap();
            let output = files(&output_state, &output_memory);
            let result = target.export_held_snapshot(3, deadline(), &output);
            let pinned = target.end_capture(3, deadline(), false).is_err();
            target.release_held_memory_map(3).unwrap();
            target.end_capture(3, deadline(), false).unwrap();
            target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
            result.unwrap();
            assert!(pinned, "full export must retain the caller's read pin");
            let mut actual = vec![0; expected.len()];
            output.memory.read_exact_at(&mut actual, 0).unwrap();
            assert_eq!(
                actual
                    .iter()
                    .zip(&expected)
                    .position(|(actual, expected)| actual != expected),
                None,
                "first differing byte after cycle {cycle}"
            );
            input.memory.read_exact_at(&mut actual, 0).unwrap();
            assert_eq!(
                actual
                    .iter()
                    .zip(&ancestor)
                    .position(|(actual, expected)| actual != expected),
                None,
                "private writes must not change the ancestor"
            );
            assert_eq!(
                output.memory.metadata().unwrap().len(),
                expected.len() as u64
            );
            eprintln!(
                "COW cycle {cycle}: logical={} allocated={}",
                output.memory.metadata().unwrap().len(),
                output.memory.metadata().unwrap().blocks() * 512
            );
            assert!(
                output.memory.metadata().unwrap().blocks() * 512 < 1 << 20,
                "restored snapshot must retain holes"
            );
            input = output;
        }
    }

    #[test]
    fn m2_cold_export_covers_complete_layout() {
        let (mut vm, _real) = paused_counter_vm();
        let report = vm.begin_capture(1, deadline()).unwrap();
        let map = vm.export_held_memory_map(1, deadline()).unwrap();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert_eq!(map.regions.len(), report.memory_layout.regions.len());
        assert_eq!(
            map.changed_ranges,
            vec![crate::memory_tracking::MemoryRange {
                image_offset: 0,
                length: 16 << 20,
            }]
        );
    }

    #[test]
    fn m2_read_pin_blocks_release_and_stale_map() {
        let (mut vm, real) = paused_counter_vm();
        vm.begin_capture(1, deadline()).unwrap();
        let map = vm.export_held_memory_map(1, deadline()).unwrap();
        let result = vm.end_capture(1, deadline(), true);
        if result.is_ok() {
            vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
            panic!("read pin must prevent resume");
        }
        assert_eq!(real.run_count(), 0);
        assert_eq!(
            vm.address_space
                .vm_memory()
                .unwrap()
                .read_obj::<u16>(GuestAddress(0x2000))
                .unwrap(),
            0,
            "rejected resume must leave RAM unchanged"
        );
        assert_eq!(vm.export_held_memory_map(1, deadline()).unwrap(), map);
        assert!(vm.release_held_memory_map(2).is_err());
        assert!(vm.export_held_memory_map(2, deadline()).is_err());
        vm.release_held_memory_map(1).unwrap();
        vm.end_capture(1, deadline(), false).unwrap();
        assert!(vm.export_held_memory_map(1, deadline()).is_err());
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    }

    fn with_loaded_counter(test: impl FnOnce(&mut Vm, &SnapshotFiles)) {
        let (mut source, _real) = paused_counter_vm();
        let config = source.vm_config.clone();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let input = files(&state, &memory);
        source.begin_capture(1, deadline()).unwrap();
        source.export_held_snapshot(1, deadline(), &input).unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        drop(source);
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll).unwrap();
        let mut vmm = vmm.lock().unwrap();
        let target = vmm.get_vm_mut().unwrap();
        let _real = RealVcpuExecution::new(target.vm_fd.clone());
        target.set_vm_config(config);
        target
            .load_snapshot_held(&mut events, Default::default(), &input, 1, deadline())
            .unwrap();
        test(target, &input);
        target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    }

    #[test]
    fn m2_cpu_dirty_survives_capture_and_failed_export() {
        with_loaded_counter(|vm, input| {
            assert!(vm
                .export_held_memory_map(1, deadline())
                .unwrap()
                .changed_ranges
                .is_empty());
            vm.release_held_memory_map(1).unwrap();
            vm.end_capture(1, deadline(), true).unwrap();
            let ram = vm.address_space.vm_memory().unwrap();
            let limit = deadline();
            while ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap() == 0 && Instant::now() < limit
            {
                std::thread::yield_now();
            }
            vm.begin_capture(2, deadline()).unwrap();
            assert_ne!(ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap(), 0);
            let map = vm.export_held_memory_map(2, deadline()).unwrap();
            assert!(
                map.changed_ranges
                    .iter()
                    .any(|range| range.image_offset <= 0x2000
                        && range.image_offset + range.length > 0x2000),
                "real KVM write must be dirty"
            );
            assert!(
                map.changed_ranges
                    .iter()
                    .map(|range| range.length)
                    .sum::<u64>()
                    < 16 << 20
            );
            assert!(
                vm.export_held_state(2, deadline(), &input.memory).is_err(),
                "live backing alias rejected"
            );
            let readonly = TempFile::new().unwrap();
            assert!(vm
                .export_held_state(2, deadline(), &File::open(readonly.as_path()).unwrap())
                .is_err());
            assert_eq!(vm.export_held_memory_map(2, deadline()).unwrap(), map);
            vm.release_held_memory_map(2).unwrap();
            vm.end_capture(2, deadline(), false).unwrap();
            vm.begin_capture(3, deadline()).unwrap();
            let retry = vm.export_held_memory_map(3, deadline()).unwrap();
            assert_eq!(
                retry.changed_ranges, map.changed_ranges,
                "capture must not reset fixed-base history"
            );
            let output = TempFile::new().unwrap();
            vm.export_held_state(3, deadline(), output.as_file())
                .unwrap();
            output.as_file().seek(SeekFrom::Start(0)).unwrap();
            let state: MicrovmState = serde_json::from_reader(output.as_file()).unwrap();
            assert_eq!(state.memory_state.unwrap().regions[0].size, 16 << 20);
            vm.release_held_memory_map(3).unwrap();
            vm.end_capture(3, deadline(), false).unwrap();
        });
    }

    #[test]
    fn m2_userspace_writes_merge_into_cumulative_map() {
        with_loaded_counter(|vm, input| {
            let ram = vm.address_space.vm_memory().unwrap();
            ram.write_slice(&[0x4c; 4096], GuestAddress(0x6000))
                .unwrap();
            let map = vm.export_held_memory_map(1, deadline()).unwrap();
            assert!(
                map.changed_ranges
                    .iter()
                    .any(|range| range.image_offset <= 0x6000
                        && range.image_offset + range.length > 0x6000),
                "userspace writes are not covered by KVM dirty logging"
            );
            assert!(
                map.changed_ranges
                    .iter()
                    .map(|range| range.length)
                    .sum::<u64>()
                    < 16 << 20
            );
            let mut rebuilt = vec![0u8; 16 << 20];
            input.memory.read_exact_at(&mut rebuilt, 0).unwrap();
            for changed in &map.changed_ranges {
                for region in &map.regions {
                    let start = changed.image_offset.max(region.image_offset);
                    let end = (changed.image_offset + changed.length)
                        .min(region.image_offset + region.length);
                    if start < end {
                        ram.read_slice(
                            &mut rebuilt[start as usize..end as usize],
                            GuestAddress(region.guest_base + start - region.image_offset),
                        )
                        .unwrap();
                    }
                }
            }
            let full_state = TempFile::new().unwrap();
            let full_ram = TempFile::new().unwrap();
            vm.export_held_snapshot(1, deadline(), &files(&full_state, &full_ram))
                .unwrap();
            let mut oracle = vec![0u8; rebuilt.len()];
            full_ram.as_file().read_exact_at(&mut oracle, 0).unwrap();
            assert_eq!(
                rebuilt, oracle,
                "incremental reconstruction must match full export at the same hold"
            );
            vm.release_held_memory_map(1).unwrap();
            vm.end_capture(1, deadline(), false).unwrap();
            vm.begin_capture(2, deadline()).unwrap();
            let again = vm.export_held_memory_map(2, deadline()).unwrap();
            assert_eq!(again.changed_ranges, map.changed_ranges);
            vm.release_held_memory_map(2).unwrap();
            vm.end_capture(2, deadline(), false).unwrap();
        });
    }

    #[test]
    fn m2_state_only_rejects_cold_live_backing_alias() {
        let (mut vm, _real) = paused_counter_vm();
        vm.begin_capture(1, deadline()).unwrap();
        let memory = vm.address_space.vm_memory().unwrap();
        let backing = memory
            .iter()
            .next()
            .unwrap()
            .file_offset()
            .unwrap()
            .file()
            .try_clone()
            .unwrap();
        let before = backing.metadata().unwrap().len();
        let result = vm.export_held_state(1, deadline(), &backing);
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert!(result.is_err(), "cold RAM file is also live backing");
        assert_eq!(backing.metadata().unwrap().len(), before);
    }

    #[test]
    fn m2_full_export_rejects_cold_live_backing_alias() {
        let (mut vm, _real) = paused_counter_vm();
        vm.begin_capture(1, deadline()).unwrap();
        let ram = vm.address_space.vm_memory().unwrap();
        let backing = ram
            .iter()
            .next()
            .unwrap()
            .file_offset()
            .unwrap()
            .file()
            .try_clone()
            .unwrap();
        let before = backing.metadata().unwrap().len();
        let output = SnapshotFiles::new(backing, TempFile::new().unwrap().into_file());
        let result = vm.export_held_snapshot(1, deadline(), &output);
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert!(
            result.is_err(),
            "full export must not truncate cold RAM through its state output"
        );
        assert_eq!(output.state.metadata().unwrap().len(), before);
    }

    #[test]
    fn m2_optional_zero_scan_preserves_ranges_cache_and_pin() {
        let (mut vm, _real) = paused_counter_vm();
        let ram = vm.address_space.vm_memory().unwrap();
        ram.write_slice(&[0u8; 4096], vm_memory::GuestAddress(0x5000))
            .unwrap();
        vm.begin_capture(1, deadline()).unwrap();
        let fast = vm
            .export_held_memory_map_without_zero_scan(1, deadline())
            .unwrap();
        assert!(fast.zero_ranges.is_empty());
        assert!(fast
            .changed_ranges
            .iter()
            .any(|r| { r.image_offset <= 0x5000 && r.image_offset + r.length > 0x5000 }));
        assert!(vm.end_capture(1, deadline(), false).is_err());
        assert!(vm
            .export_held_memory_map_without_zero_scan(2, deadline())
            .is_err());
        let classified = vm.export_held_memory_map(1, deadline()).unwrap();
        assert_eq!(classified.changed_ranges, fast.changed_ranges);
        assert_eq!(classified.regions, fast.regions);
        assert!(classified
            .zero_ranges
            .iter()
            .any(|r| { r.image_offset <= 0x5000 && r.image_offset + r.length > 0x5000 }));
        let fast_again = vm
            .export_held_memory_map_without_zero_scan(1, deadline())
            .unwrap();
        assert_eq!(fast_again, fast);
        assert_eq!(
            vm.export_held_memory_map(1, deadline()).unwrap(),
            classified
        );
        vm.release_held_memory_map(1).unwrap();
        vm.end_capture(1, deadline(), false).unwrap();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
    }

    #[test]
    fn m2_actions_preserve_read_pin_and_owned_state_output() {
        use crate::api::v1::{VmmAction, VmmData, VmmService};
        use crate::snapshot::capture::SnapshotStateFile;
        use crossbeam_channel::unbounded as channel;
        let (vm, _real) = paused_counter_vm();
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll).unwrap();
        let mut vmm = vmm.lock().unwrap();
        *vmm.get_vm_mut().unwrap() = vm;
        let (request_tx, request_rx) = channel();
        let (response_tx, response_rx) = channel();
        let mut service = VmmService::new(request_rx, response_tx);
        let mut call = |action| {
            request_tx.send(Box::new(action)).unwrap();
            service.run_vmm_action(&mut vmm, &mut events).unwrap();
            *response_rx.recv().unwrap()
        };
        assert!(matches!(
            call(VmmAction::BeginCapture {
                generation: 1,
                deadline: deadline()
            }),
            Ok(VmmData::CaptureReport(_))
        ));
        assert!(matches!(
            call(VmmAction::ExportHeldMemoryMapWithoutZeroScan {
                generation: 1,
                deadline: deadline()
            }),
            Ok(VmmData::FrozenMemoryMap(map)) if map.zero_ranges.is_empty()
        ));
        assert!(matches!(
            call(VmmAction::ExportHeldMemoryMap {
                generation: 1,
                deadline: deadline()
            }),
            Ok(VmmData::FrozenMemoryMap(_))
        ));
        assert!(call(VmmAction::EndCapture {
            generation: 1,
            deadline: deadline(),
            resume: true
        })
        .is_err());
        let output = Arc::new(TempFile::new().unwrap().into_file());
        assert!(matches!(
            call(VmmAction::ExportHeldState {
                generation: 1,
                deadline: deadline(),
                state_file: SnapshotStateFile(output.clone())
            }),
            Ok(VmmData::Empty)
        ));
        assert!(output.metadata().unwrap().len() > 0);
        assert!(call(VmmAction::ReleaseHeldMemoryMap { generation: 2 }).is_err());
        assert!(matches!(
            call(VmmAction::ReleaseHeldMemoryMap { generation: 1 }),
            Ok(VmmData::Empty)
        ));
        assert!(matches!(
            call(VmmAction::EndCapture {
                generation: 1,
                deadline: deadline(),
                resume: false
            }),
            Ok(VmmData::Empty)
        ));
        vmm.get_vm_mut()
            .unwrap()
            .vcpu_manager()
            .unwrap()
            .exit_all_vcpus()
            .unwrap();
    }

    fn configure_disk(vm: &mut Vm, path: &std::path::Path) {
        configure_disk_slot(vm, path, false);
    }

    fn configure_disk_slot(vm: &mut Vm, path: &std::path::Path, is_volume_slot: bool) {
        use crate::device_manager::blk_dev_mgr::BlockDeviceConfigInfo;
        let context = DeviceOpContext::create_boot_ctx(vm, None);
        let (sender, _) = std::sync::mpsc::channel();
        vm.device_manager
            .block_manager
            .insert_device(
                context,
                BlockDeviceConfigInfo {
                    drive_id: "root".into(),
                    path_on_host: path.into(),
                    is_volume_slot,
                    is_direct: false,
                    num_queues: 1,
                    queue_size: 16,
                    use_pci_bus: Some(false),
                    use_shared_irq: Some(false),
                    use_generic_irq: Some(true),
                    ..Default::default()
                },
                sender,
            )
            .unwrap();
    }

    fn paused_counter_vm_with_disk(disk: Option<&std::path::Path>) -> (Vm, RealVcpuExecution) {
        paused_counter_vm_with_disk_slot(disk, false, 16)
    }

    fn paused_counter_vm_with_disk_slot(
        disk: Option<&std::path::Path>,
        slot: bool,
        mem_size_mib: usize,
    ) -> (Vm, RealVcpuExecution) {
        let mut vm = super::super::tests::create_vm_instance();
        let real = RealVcpuExecution::new(vm.vm_fd.clone());
        let config = VmConfigInfo {
            vcpu_count: 1,
            max_vcpu_count: 1,
            mem_size_mib,
            mem_type: "shmem".to_owned(),
            cpu_pm: "off".to_owned(),
            ..Default::default()
        };
        vm.set_vm_config(config);
        if let Some(path) = disk {
            configure_disk_slot(&mut vm, path, slot);
        }
        vm.init_guest_memory().unwrap();
        let vm_as = vm.vm_as().cloned().unwrap();
        vm.init_vcpu_manager(vm_as.clone(), Default::default())
            .unwrap();
        vm.init_microvm_from_snapshot(vm.epoll_manager.clone(), vm_as, TimestampUs::default())
            .unwrap();
        if disk.is_some() {
            let device = vm
                .device_manager
                .block_manager
                .iter()
                .next()
                .unwrap()
                .device
                .as_ref()
                .unwrap();
            let mmio = device
                .as_any()
                .downcast_ref::<crate::device_manager::DbsMmioV2Device>()
                .unwrap();
            let mut state = mmio.save_state();
            state.queues[0].queue = dbs_virtio_devices::persist::VirtioQueueState {
                max_size: 16,
                size: 16,
                ready: true,
                desc_table: 0x4000,
                avail_ring: 0x4200,
                used_ring: 0x4300,
                ..Default::default()
            };
            if slot {
                let mut guard = mmio.state();
                let inner = guard.get_inner_device_mut();
                inner.set_acked_features(0, 6); // SIZE_MAX and SEG_MAX; never guest RO.
                inner.set_acked_features(1, 1); // VERSION_1.
                state.queues[0].queue.next_avail = 7;
                state.queues[0].queue.next_used = 7;
                let memory = vm.address_space.vm_memory().unwrap();
                memory.write_obj(7u16, GuestAddress(0x4202)).unwrap();
                memory.write_obj(7u16, GuestAddress(0x4302)).unwrap();
            }
            state.driver_status = 0xf;
            state.device_activated = true;
            mmio.restore_state(&state).unwrap();
        }
        let memory = vm.address_space.vm_memory().unwrap();
        // Real-mode inc word [0x2000]; jump back to inc. Execution is observable.
        memory
            .write_slice(&[0xff, 0x06, 0x00, 0x20, 0xeb, 0xfa], GuestAddress(0x1000))
            .unwrap();
        memory.write_obj(0u16, GuestAddress(0x2000)).unwrap();
        let msrs = vm.kvm.supported_msrs(0).unwrap();
        let mut manager = vm.vcpu_manager().unwrap();
        let mut states = manager
            .vcpus_mut()
            .into_iter()
            .map(|cpu| Persist::save_state(cpu, msrs.as_slice()).unwrap())
            .collect::<Vec<_>>();
        states[0].regs.rip = 0x1000;
        states[0].regs.rflags = 2;
        states[0].sregs.cs.base = 0;
        states[0].sregs.cs.selector = 0;
        states[0].sregs.ds.base = 0;
        states[0].sregs.ds.selector = 0;
        Persist::restore_state(&mut *manager, &states, ()).unwrap();
        manager.start_vcpus(1, Default::default(), false).unwrap();
        drop(manager);
        vm.set_instance_state(InstanceState::Paused);
        (vm, real)
    }

    #[test]
    fn export_requires_current_capture_generation() {
        let (mut vm, _real) = paused_counter_vm();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let output = files(&state, &memory);
        output.state.write_all_at(b"state sentinel", 0).unwrap();
        output.memory.write_all_at(b"memory sentinel", 0).unwrap();
        let report = vm.begin_capture(1, deadline()).unwrap();
        assert_eq!(report.generation, 1);
        assert!(vm.export_held_snapshot(2, deadline(), &output).is_err());
        let mut state_bytes = [0; 14];
        let mut memory_bytes = [0; 15];
        output.state.read_exact_at(&mut state_bytes, 0).unwrap();
        output.memory.read_exact_at(&mut memory_bytes, 0).unwrap();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert_eq!(&state_bytes, b"state sentinel");
        assert_eq!(&memory_bytes, b"memory sentinel");
        assert_eq!(output.state.metadata().unwrap().len(), 14);
        assert_eq!(output.memory.metadata().unwrap().len(), 15);
    }

    #[test]
    fn capture_export_uses_open_files_after_path_replacement() {
        let (mut vm, _real) = paused_counter_vm();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let moved_state = TempFile::new().unwrap();
        let moved_memory = TempFile::new().unwrap();
        let output = files(&state, &memory);
        std::fs::rename(state.as_path(), moved_state.as_path()).unwrap();
        std::fs::rename(memory.as_path(), moved_memory.as_path()).unwrap();
        std::fs::write(state.as_path(), b"state replacement").unwrap();
        std::fs::write(memory.as_path(), b"memory replacement").unwrap();
        vm.begin_capture(1, deadline()).unwrap();
        vm.export_held_snapshot(1, deadline(), &output).unwrap();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert_eq!(
            std::fs::read(state.as_path()).unwrap(),
            b"state replacement"
        );
        assert_eq!(
            std::fs::read(memory.as_path()).unwrap(),
            b"memory replacement"
        );
        assert_eq!(output.memory.metadata().unwrap().len(), 16 * 1024 * 1024);
        assert_eq!(
            std::fs::metadata(moved_memory.as_path()).unwrap().len(),
            16 * 1024 * 1024
        );
        let saved = MicrovmState::load_from_file(moved_state.as_path()).unwrap();
        assert!(saved.capture_cpu.is_some());
    }

    #[test]
    fn capture_legacy_snapshot_roundtrip_really_executes() {
        let (mut source, _source_real) = paused_counter_vm();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        source
            .save_microvm(state.as_path(), memory.as_path(), false)
            .unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        let saved = MicrovmState::load_from_file(state.as_path()).unwrap();
        assert!(saved.capture_cpu.is_none());
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll).unwrap();
        let mut vmm = vmm.lock().unwrap();
        let target = vmm.get_vm_mut().unwrap();
        let _target_real = RealVcpuExecution::new(target.vm_fd.clone());
        target.set_vm_config(source.vm_config.clone());
        target
            .start_microvm_from_snapshot(
                &mut events,
                Default::default(),
                state.as_path(),
                memory.as_path(),
                false,
            )
            .unwrap();
        let ram = target.address_space.vm_memory().unwrap();
        let end = deadline();
        while ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap() == 0 && Instant::now() < end {
            std::thread::yield_now();
        }
        let ran = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        let state = target.instance_state();
        target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert_eq!(state, InstanceState::Running);
        assert_ne!(ran, 0, "legacy restore must still execute real KVM_RUN");
    }

    #[test]
    fn capture_legacy_resume_cannot_bypass_hold() {
        let (mut vm, _real) = paused_counter_vm();
        vm.begin_capture(1, deadline()).unwrap();
        let result = vm.resume_all_vcpus_with_downtime();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert!(
            result.is_err(),
            "legacy resume must not bypass a capture session"
        );
    }

    #[test]
    fn capture_api_returns_proof_and_rejects_legacy_resume() {
        use crate::api::v1::{VmmAction, VmmActionError, VmmData, VmmService};
        use crossbeam_channel::unbounded as channel;
        let (vm, _real) = paused_counter_vm();
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll).unwrap();
        let mut vmm = vmm.lock().unwrap();
        *vmm.get_vm_mut().unwrap() = vm;
        let (request_tx, request_rx) = channel();
        let (response_tx, response_rx) = channel();
        let mut service = VmmService::new(request_rx, response_tx);
        request_tx
            .send(Box::new(VmmAction::BeginCapture {
                generation: 1,
                deadline: deadline(),
            }))
            .unwrap();
        service.run_vmm_action(&mut vmm, &mut events).unwrap();
        match *response_rx.recv().unwrap() {
            Ok(VmmData::CaptureReport(report)) => {
                assert_eq!(report.generation, 1);
                assert_eq!(report.vcpu_acks.len(), 1);
            }
            other => panic!("unexpected capture response {:?}", other),
        }
        request_tx.send(Box::new(VmmAction::ResumeMicroVm)).unwrap();
        service.run_vmm_action(&mut vmm, &mut events).unwrap();
        let blocked = matches!(
            *response_rx.recv().unwrap(),
            Err(VmmActionError::Capture(_))
        );
        request_tx
            .send(Box::new(VmmAction::EndCapture {
                generation: 1,
                deadline: deadline(),
                resume: true,
            }))
            .unwrap();
        service.run_vmm_action(&mut vmm, &mut events).unwrap();
        let released = matches!(*response_rx.recv().unwrap(), Ok(VmmData::Empty));
        vmm.get_vm_mut()
            .unwrap()
            .vcpu_manager()
            .unwrap()
            .exit_all_vcpus()
            .unwrap();
        assert!(blocked);
        assert!(released);
    }

    #[test]
    fn capture_rejects_invalid_msr_and_xsave_before_restore() {
        let (mut vm, _real) = paused_counter_vm();
        let state_file = TempFile::new().unwrap();
        let memory_file = TempFile::new().unwrap();
        let output = files(&state_file, &memory_file);
        vm.begin_capture(1, deadline()).unwrap();
        vm.export_held_snapshot(1, deadline(), &output).unwrap();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        let mut target = super::super::tests::create_vm_instance();
        target.set_vm_config(vm.vm_config.clone());
        let original =
            serde_json::to_value(MicrovmState::load_from_file(state_file.as_path()).unwrap())
                .unwrap();
        let mut invalid = serde_json::from_value::<MicrovmState>(original.clone()).unwrap();
        invalid.vcpu_states[0].msrs[0].as_mut_slice()[0].index = u32::MAX;
        invalid.save_to_file(state_file.as_path()).unwrap();
        assert!(
            target.read_held_snapshot(&output).is_err(),
            "unknown saved MSR must be rejected before applying state"
        );
        let mut invalid = serde_json::from_value::<MicrovmState>(original.clone()).unwrap();
        invalid.vcpu_states[0].xsave.region[129] |= 1 << 31;
        invalid.save_to_file(state_file.as_path()).unwrap();
        assert!(
            target.read_held_snapshot(&output).is_err(),
            "unsupported XSAVE feature must be rejected before applying state"
        );
        let mut invalid = serde_json::from_value::<MicrovmState>(original).unwrap();
        invalid.capture_cpu.as_mut().unwrap().cpuid.as_mut_slice()[0].eax ^= 1;
        invalid.save_to_file(state_file.as_path()).unwrap();
        assert!(
            target.read_held_snapshot(&output).is_err(),
            "changed CPU requirements must not be normalized away"
        );
        assert!(target.vm_as().is_none());
    }

    #[test]
    fn capture_full_layout_handles_gpa_hole() {
        let (mut vm, _real) = paused_counter_vm_with_disk_slot(None, false, 8192);
        let layout = vm.address_space.capture_layout().unwrap();
        assert!(layout.regions.len() > 1);
        assert_eq!(layout.total_bytes, 8 * 1024 * 1024 * 1024);
        let mut packed = 0;
        for region in &layout.regions {
            assert_eq!(region.file_offset, packed);
            assert_ne!(region.host_addr, 0);
            assert_eq!(
                vm.address_space
                    .get_base_to_slot_map()
                    .lock()
                    .unwrap()
                    .get(&region.guest_addr),
                Some(&region.kvm_slot)
            );
            packed += region.size;
        }
        assert_eq!(packed, layout.total_bytes);
        assert!(layout
            .regions
            .windows(2)
            .any(|pair| pair[0].guest_addr + pair[0].size < pair[1].guest_addr));
        let ram = vm.address_space.vm_memory().unwrap();
        for (index, region) in layout.regions.iter().enumerate() {
            ram.write_obj(
                0x71u8 + index as u8,
                GuestAddress(region.guest_addr + 0x3000),
            )
            .unwrap();
        }
        let config = vm.vm_config.clone();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let input = files(&state, &memory);
        vm.begin_capture(1, deadline()).unwrap();
        let result = vm.export_held_snapshot(1, deadline(), &input);
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        result.unwrap();
        drop(ram);
        drop(vm);
        assert_eq!(input.memory.metadata().unwrap().len(), layout.total_bytes);
        assert!(input.memory.metadata().unwrap().blocks() * 512 < 1 << 20);
        for (index, region) in layout.regions.iter().enumerate() {
            let mut marker = [0];
            input
                .memory
                .read_exact_at(&mut marker, region.file_offset + 0x3000)
                .unwrap();
            assert_eq!(marker, [0x71 + index as u8]);
            let mut tail = [1; 4096];
            input
                .memory
                .read_exact_at(&mut tail, region.file_offset + region.size - 4096)
                .unwrap();
            assert_eq!(tail, [0; 4096]);
        }
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll).unwrap();
        let mut guard = vmm.lock().unwrap();
        let target = guard.get_vm_mut().unwrap();
        let _real = RealVcpuExecution::new(target.vm_fd.clone());
        target.set_vm_config(config);
        target
            .load_snapshot_held(&mut events, Default::default(), &input, 1, deadline())
            .unwrap();
        let high = layout.regions.last().unwrap();
        let ram = target.address_space.vm_memory().unwrap();
        ram.write_obj(0u8, GuestAddress(high.guest_addr + 0x3000))
            .unwrap();
        ram.write_obj(0x93u8, GuestAddress(high.guest_addr + 0x4000))
            .unwrap();
        let output_state = TempFile::new().unwrap();
        let output_memory = TempFile::new().unwrap();
        let output = files(&output_state, &output_memory);
        let result = target.export_held_snapshot(1, deadline(), &output);
        target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        result.unwrap();
        assert_eq!(output.memory.metadata().unwrap().len(), layout.total_bytes);
        assert!(output.memory.metadata().unwrap().blocks() * 512 < 1 << 20);
        for (index, region) in layout.regions.iter().enumerate() {
            let mut page = [0; 4096];
            output
                .memory
                .read_exact_at(&mut page, region.file_offset + 0x3000)
                .unwrap();
            let mut expected = [0; 4096];
            if index + 1 != layout.regions.len() {
                expected[0] = 0x71 + index as u8;
            }
            assert_eq!(page, expected);
            output
                .memory
                .read_exact_at(&mut page, region.file_offset + region.size - 4096)
                .unwrap();
            assert_eq!(page, [0; 4096]);
        }
        let mut marker = [0];
        output
            .memory
            .read_exact_at(&mut marker, high.file_offset + 0x4000)
            .unwrap();
        assert_eq!(marker, [0x93]);
    }

    #[test]
    fn capture_running_cpu_is_frozen_through_full_export_and_release() {
        let (mut vm, _real) = paused_counter_vm();
        vm.resume_all_vcpus_with_downtime().unwrap();
        let ram = vm.address_space.vm_memory().unwrap();
        let end = deadline();
        while ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap() == 0 && Instant::now() < end {
            std::thread::yield_now();
        }
        assert_ne!(
            ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap(),
            0,
            "the capture source must really execute"
        );
        let report = vm.begin_capture(1, deadline()).unwrap();
        assert_eq!(report.vcpu_acks.len(), 1);
        assert_eq!(report.vcpu_acks[0].generation, 1);
        let frozen = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let after_hold = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let output = files(&state, &memory);
        vm.export_held_snapshot(1, deadline(), &output).unwrap();
        let mut bytes = [0; 2];
        output.memory.read_exact_at(&mut bytes, 0x2000).unwrap();
        vm.end_capture(1, deadline(), true).unwrap();
        let end = deadline();
        while ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap() == frozen && Instant::now() < end {
            std::thread::yield_now();
        }
        let resumed = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        let stale = vm.begin_capture(1, deadline());
        let next = vm.begin_capture(2, deadline()).unwrap();
        vm.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert_eq!(after_hold, frozen);
        assert_eq!(u16::from_le_bytes(bytes), frozen);
        assert_eq!(output.memory.metadata().unwrap().len(), 16 * 1024 * 1024);
        assert_ne!(resumed, frozen);
        assert!(matches!(stale, Err(CaptureError::Rejected(_))));
        assert_eq!(next.generation, 2);
    }

    #[test]
    fn load_held_rejects_unknown_device_writer_before_allocation() {
        let (mut source, _real) = paused_counter_vm();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let snapshot = files(&state, &memory);
        source.begin_capture(1, deadline()).unwrap();
        source
            .export_held_snapshot(1, deadline(), &snapshot)
            .unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        let mut value =
            serde_json::to_value(MicrovmState::load_from_file(state.as_path()).unwrap()).unwrap();
        value["device_states"]["unknown_dma_writer"] = serde_json::json!({"active": true});
        std::fs::write(state.as_path(), serde_json::to_vec(&value).unwrap()).unwrap();
        let mut target = super::super::tests::create_vm_instance();
        target.set_vm_config(source.vm_config.clone());
        assert!(
            target.read_held_snapshot(&snapshot).is_err(),
            "an unmodeled writer must not be silently dropped by serde"
        );
        assert!(target.vm_as().is_none());
    }

    #[test]
    fn load_held_never_runs_vcpu_or_device() {
        let source_disk = TempFile::new().unwrap();
        let target_disk = TempFile::new().unwrap();
        let source_observer = files(&source_disk, &source_disk).state;
        source_observer.set_len(4096).unwrap();
        let target_observer = files(&target_disk, &target_disk).state;
        target_observer.set_len(4096).unwrap();
        let (mut source, _source_real) = paused_counter_vm_with_disk(Some(source_disk.as_path()));
        let config = source.vm_config.clone();
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let report = source.begin_capture(1, deadline()).unwrap();
        assert_eq!(report.device_acks.len(), 1);
        assert_eq!(report.device_acks[0].device_id, "block:root/q0");
        let source_ram = source.address_space.vm_memory().unwrap();
        // Three real descriptors: OUT request header, 512 data bytes, status.
        for (index, address, size, flags, next) in [
            (0u64, 0x5000u64, 16u32, 1u16, 1u16),
            (1, 0x6000, 512, 1, 2),
            (2, 0x7000, 1, 2, 0),
        ] {
            let descriptor = GuestAddress(0x4000 + index * 16);
            source_ram.write_obj(address, descriptor).unwrap();
            source_ram
                .write_obj(size, GuestAddress(descriptor.0 + 8))
                .unwrap();
            source_ram
                .write_obj(flags, GuestAddress(descriptor.0 + 12))
                .unwrap();
            source_ram
                .write_obj(next, GuestAddress(descriptor.0 + 14))
                .unwrap();
        }
        source_ram.write_obj(1u32, GuestAddress(0x5000)).unwrap();
        source_ram
            .write_slice(&[0x5a; 512], GuestAddress(0x6000))
            .unwrap();
        source_ram.write_obj(1u16, GuestAddress(0x4202)).unwrap();
        source_ram.write_obj(0u16, GuestAddress(0x4204)).unwrap();
        source
            .export_held_snapshot(1, deadline(), &files(&state, &memory))
            .unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        drop(source);
        let epoll = EpollManager::default();
        let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
            epoll.clone(),
        )));
        let mut events = EventManager::new(&vmm, epoll).unwrap();
        let mut vmm = vmm.lock().unwrap();
        let target = vmm.get_vm_mut().unwrap();
        let _target_real = RealVcpuExecution::new(target.vm_fd.clone());
        target.set_vm_config(config);
        configure_disk(target, target_disk.as_path());
        let report = target
            .load_snapshot_held(
                &mut events,
                Default::default(),
                &files(&state, &memory),
                7,
                deadline(),
            )
            .unwrap();
        assert_eq!(report.generation, 7);
        assert_eq!(report.vcpu_acks.len(), 1);
        assert_eq!(report.device_acks.len(), 1);
        assert!(report.device_acks[0].flush_completed);
        let input = files(&state, &memory);
        let state_len = input.state.metadata().unwrap().len();
        let memory_len = input.memory.metadata().unwrap().len();
        assert!(
            target.export_held_snapshot(7, deadline(), &input).is_err(),
            "export must not truncate a live mmap backing"
        );
        assert_eq!(input.state.metadata().unwrap().len(), state_len);
        assert_eq!(input.memory.metadata().unwrap().len(), memory_len);
        let ram = target.address_space.vm_memory().unwrap();
        let initial = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let held = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        let held_used = ram.read_obj::<u16>(GuestAddress(0x4302)).unwrap();
        let mut held_disk = [0; 512];
        target_observer.read_exact_at(&mut held_disk, 0).unwrap();
        let held_runs = _target_real.run_count();
        target.end_capture(7, deadline(), true).unwrap();
        let end = deadline();
        while ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap() == initial && Instant::now() < end
        {
            std::thread::yield_now();
        }
        let resumed = ram.read_obj::<u16>(GuestAddress(0x2000)).unwrap();
        while ram.read_obj::<u16>(GuestAddress(0x4302)).unwrap() == 0 && Instant::now() < end {
            std::thread::yield_now();
        }
        let resumed_used = ram.read_obj::<u16>(GuestAddress(0x4302)).unwrap();
        let mut resumed_disk = [0; 512];
        target_observer.read_exact_at(&mut resumed_disk, 0).unwrap();
        target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        assert_eq!(held_runs, 0, "held restore must not even enter KVM_RUN");
        assert!(_target_real.run_count() > 0);
        assert_eq!(initial, 0);
        assert_eq!(held, initial);
        assert_eq!(held_used, 0);
        assert_eq!(held_disk, [0; 512]);
        assert_eq!(resumed_used, 1);
        assert_eq!(resumed_disk, [0x5a; 512]);
        let region = ram.iter().next().unwrap();
        assert_eq!(
            region.flags() & libc::MAP_SHARED,
            0,
            "held restore metadata must describe private backing"
        );
        assert_eq!(
            region
                .file_offset()
                .unwrap()
                .file()
                .metadata()
                .unwrap()
                .ino(),
            memory.as_file().metadata().unwrap().ino(),
            "held region must retain the real snapshot inode"
        );
        assert_ne!(
            resumed, initial,
            "fixture must actually run after explicit release"
        );
    }

    #[test]
    fn m2_slot_rejects_template_contract_changes_before_allocation() {
        let disk = TempFile::new().unwrap();
        disk.as_file().set_len(4096).unwrap();
        let (mut source, _real) = paused_counter_vm_with_disk_slot(Some(disk.as_path()), true, 16);
        let state = TempFile::new().unwrap();
        let memory = TempFile::new().unwrap();
        let snapshot = files(&state, &memory);
        source.begin_capture(1, deadline()).unwrap();
        source
            .export_held_snapshot(1, deadline(), &snapshot)
            .unwrap();
        source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
        let config = source.vm_config.clone();
        let saved =
            serde_json::to_value(MicrovmState::load_from_file(state.as_path()).unwrap()).unwrap();
        drop(source);
        for (slot, guest_ro, backing_ro) in [
            (false, false, None),
            (true, true, None),
            (true, false, Some(true)),
        ] {
            let mut modified = saved.clone();
            let disk_config = &mut modified["device_states"]["block"]["devices"][0]["config"];
            disk_config["is_volume_slot"] = serde_json::json!(slot);
            disk_config["is_read_only"] = serde_json::json!(guest_ro);
            disk_config["backing_read_only"] = serde_json::json!(backing_ro);
            std::fs::write(state.as_path(), serde_json::to_vec(&modified).unwrap()).unwrap();
            let mut target = super::super::tests::create_vm_instance();
            target.set_vm_config(config.clone());
            configure_disk_slot(&mut target, disk.as_path(), true);
            assert!(
                target.read_held_snapshot(&snapshot).is_err(),
                "reject changed slot contract before allocating guest RAM"
            );
            assert!(target.vm_as().is_none());
        }
    }

    #[test]
    fn m2_slot_backing_ro_rejects_raw_write() {
        use crate::device_manager::{blk_dev_mgr::RestoreBlockBinding, DbsMmioV2Device};
        for (capacity, read_only) in [(512u64, true), (16384, true), (16384, false)] {
            let placeholder = TempFile::new().unwrap();
            placeholder.as_file().set_len(4096).unwrap();
            let backing = TempFile::new().unwrap();
            backing.as_file().set_len(capacity).unwrap();
            backing
                .as_file()
                .write_all_at(&[0x3c; 512], capacity - 512)
                .unwrap();
            let (mut source, _source_real) =
                paused_counter_vm_with_disk_slot(Some(placeholder.as_path()), true, 16);
            let config = source.vm_config.clone();
            source.begin_capture(1, deadline()).unwrap();
            let ram = source.address_space.vm_memory().unwrap();
            // OUT, read last valid sector, then read one sector past the new end.
            for (request, kind, sector, payload) in [
                (0u64, 1u32, 0u64, 0x6000u64),
                (1, 0, capacity / 512 - 1, 0x6200),
                (2, 0, capacity / 512, 0x6400),
            ] {
                let first = request * 3;
                let header = 0x5000 + request * 32;
                for (idx, addr, len, flags, next) in [
                    (first, header, 16u32, 1u16, first + 1),
                    (
                        first + 1,
                        payload,
                        512,
                        if kind == 0 { 3 } else { 1 },
                        first + 2,
                    ),
                    (first + 2, 0x7000 + request, 1, 2, 0),
                ] {
                    let desc = 0x4000 + idx * 16;
                    ram.write_obj(addr, GuestAddress(desc)).unwrap();
                    ram.write_obj(len, GuestAddress(desc + 8)).unwrap();
                    ram.write_obj(flags, GuestAddress(desc + 12)).unwrap();
                    ram.write_obj(next as u16, GuestAddress(desc + 14)).unwrap();
                }
                ram.write_obj(kind, GuestAddress(header)).unwrap();
                ram.write_obj(sector, GuestAddress(header + 8)).unwrap();
                ram.write_obj(first as u16, GuestAddress(0x4204 + (7 + request) * 2))
                    .unwrap();
                ram.write_obj(0xffu8, GuestAddress(0x7000 + request))
                    .unwrap();
            }
            ram.write_slice(&[0x5a; 512], GuestAddress(0x6000)).unwrap();
            ram.write_obj(10u16, GuestAddress(0x4202)).unwrap();
            let state = TempFile::new().unwrap();
            let memory = TempFile::new().unwrap();
            let snapshot = files(&state, &memory);
            source
                .export_held_snapshot(1, deadline(), &snapshot)
                .unwrap();
            source.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
            drop(source);

            let epoll = EpollManager::default();
            let vmm = Arc::new(Mutex::new(crate::vmm::tests::create_vmm_instance(
                epoll.clone(),
            )));
            let mut events = EventManager::new(&vmm, epoll).unwrap();
            let mut vmm = vmm.lock().unwrap();
            let target = vmm.get_vm_mut().unwrap();
            let real = RealVcpuExecution::new(target.vm_fd.clone());
            target.set_vm_config(config);
            configure_disk_slot(target, placeholder.as_path(), true);
            let mut snapshot = snapshot;
            snapshot.block_bindings.push(RestoreBlockBinding {
                slot_id: "root".into(),
                path: backing.as_path().into(),
                capacity_bytes: capacity,
                backing_read_only: read_only,
            });
            let loaded = target.load_snapshot_held(
                &mut events,
                Default::default(),
                &snapshot,
                7,
                deadline(),
            );
            if loaded.is_err() {
                if let Ok(mut cpus) = target.vcpu_manager() {
                    cpus.exit_all_vcpus().unwrap();
                }
            }
            loaded.unwrap();
            let device = target
                .device_manager
                .block_manager
                .iter()
                .next()
                .unwrap()
                .device
                .as_ref()
                .unwrap()
                .clone();
            let mmio = device.as_any().downcast_ref::<DbsMmioV2Device>().unwrap();
            let transport = mmio.save_state();
            let mut capacity_config = [0; 8];
            let (device_state, _) = crate::device_manager::persist::save_device_state::<
                dbs_virtio_devices::block::Block<
                    crate::address_space_manager::GuestAddressSpaceImpl,
                >,
            >(&device, ())
            .unwrap();
            mmio.state()
                .get_inner_device_mut()
                .read_config(0, &mut capacity_config)
                .unwrap();
            let ram = target.address_space.vm_memory().unwrap();
            let held_used = ram.read_obj::<u16>(GuestAddress(0x4302)).unwrap();
            let held_runs = real.run_count();
            target.end_capture(7, deadline(), true).unwrap();
            let end = deadline();
            while ram.read_obj::<u16>(GuestAddress(0x4302)).unwrap() != 10 && Instant::now() < end {
                std::thread::yield_now();
            }
            target.vcpu_manager().unwrap().exit_all_vcpus().unwrap();
            assert_eq!(held_used, 7);
            assert_eq!(held_runs, 0);
            assert_eq!(device_state.acked_features, 0x1_0000_0006);
            assert_eq!(transport.queues[0].queue.next_avail, 7);
            assert_eq!(transport.queues[0].queue.next_used, 7);
            assert_eq!(capacity_config, (capacity / 512).to_le_bytes());
            assert_eq!(transport.config_generation, 1);
            assert_ne!(
                transport.interrupt_status & 2,
                0,
                "capacity change must notify the guest"
            );
            assert_eq!(ram.read_obj::<u16>(GuestAddress(0x4302)).unwrap(), 10);
            assert_eq!(
                ram.read_obj::<u8>(GuestAddress(0x7000)).unwrap(),
                if read_only { 1 } else { 0 }
            );
            assert_eq!(ram.read_obj::<u8>(GuestAddress(0x7001)).unwrap(), 0);
            assert_eq!(ram.read_obj::<u8>(GuestAddress(0x7002)).unwrap(), 1);
            let mut payload = [0; 512];
            ram.read_slice(&mut payload, GuestAddress(0x6200)).unwrap();
            assert_eq!(payload, [0x3c; 512]);
            backing.as_file().read_exact_at(&mut payload, 0).unwrap();
            assert_eq!(
                payload,
                if !read_only {
                    [0x5a; 512]
                } else if capacity == 512 {
                    [0x3c; 512]
                } else {
                    [0; 512]
                }
            );
        }
    }
}
