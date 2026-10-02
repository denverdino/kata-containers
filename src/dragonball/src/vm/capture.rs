// Copyright (C) 2026 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::device_manager::capture::DeviceCaptureError;
use crate::snapshot::capture::{CaptureError, CaptureReport, CpuRequirements, SnapshotFiles};
use crate::snapshot::{MicrovmState, SnapshotError};
use dbs_snapshot::Persist;
use dbs_virtio_devices::capture::CaptureGeneration;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::{MutexGuard, TryLockError};
use std::time::Instant;

type CaptureResult<T> = std::result::Result<T, CaptureError>;

pub(super) struct VmCaptureSession {
    generation: u64,
    report: Option<CaptureReport>,
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
            if let Some(source) = &self.capture_source {
                for output in [&files.state, &files.memory] {
                    if same_file(output, &source.state)? || same_file(output, &source.memory)? {
                        return Err(SnapshotError::InvalidSnapshot(
                            "output aliases a live snapshot backing".into(),
                        ));
                    }
                }
            }
            if self.address_space.capture_layout()? != expected {
                return Err(SnapshotError::InvalidSnapshot(
                    "held memory layout changed".into(),
                ));
            }
            let msrs = self.kvm.supported_msrs(0).map_err(SnapshotError::Kvm)?;
            let states = self
                .capture_cpu_manager(deadline)
                .map_err(|e| SnapshotError::InvalidState(e.to_string()))?
                .capture_save(msrs.as_slice(), deadline)?;
            let mut state = self.snapshot_metadata_paused(states)?;
            #[cfg(feature = "virtio-vsock")]
            {
                state.device_states.vsock = None;
            }
            #[cfg(any(feature = "virtio-fs", feature = "vhost-user-fs"))]
            {
                state.device_states.fs = None;
            }
            state.capture_cpu = Some(CpuRequirements {
                cpuid: host_cpu_requirements(&self.kvm)?,
                msr_indices: msrs.as_slice().to_vec(),
            });
            let mut memory = files.memory.try_clone()?;
            state.memory_state = Some(self.address_space.save_state(&mut memory)?);
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
        self.validate_capture_request(generation, deadline)?;
        if self.is_vm_initialized() {
            return Err(CaptureError::Rejected("VM is already initialized".into()));
        }
        self.device_manager
            .validate_capture_profile()
            .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        let state = self
            .read_held_snapshot(files)
            .map_err(|e| CaptureError::Rejected(e.to_string()))?;
        self.last_capture_generation = generation;
        self.capture_session = Some(VmCaptureSession {
            generation,
            report: None,
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
            let vm_as = self
                .vm_as()
                .cloned()
                .ok_or(StartMicroVmError::GuestMemoryNotInitialized)?;
            self.init_vcpu_manager(
                vm_as.clone(),
                filters.get(VCPU_THREAD).cloned().unwrap_or_default(),
            )
            .map_err(StartMicroVmError::Vcpu)?;
            self.init_microvm_from_snapshot(events.epoll_manager(), vm_as, TimestampUs::default())?;
            self.device_manager
                .arm_capture_restore(CaptureGeneration(generation))
                .map_err(|e| StartMicroVmError::RestoreMicroVm(e.to_string()))?;
            self.restore_held_state(&state)
                .map_err(|e| StartMicroVmError::RestoreMicroVm(e.to_string()))?;
            self.register_events(events)?;
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
        let vcpu_acks = self
            .capture_cpu_manager(deadline)?
            .capture_pause(generation, deadline)
            .map_err(terminal)?;
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
        let value: serde_json::Value =
            serde_json::from_reader(file).map_err(crate::snapshot::PersistError::from)?;
        crate::snapshot::check_epoch(
            value
                .get("header")
                .and_then(|h| h.get("format_epoch"))
                .and_then(|e| e.as_u64())
                .unwrap_or(0),
            crate::snapshot::FORMAT_EPOCH,
        )?;
        if let Some(devices) = value.get("device_states").and_then(|v| v.as_object()) {
            if devices
                .iter()
                .any(|(name, value)| name != "block" && name != "virtio_net" && !value.is_null())
            {
                return Err(SnapshotError::InvalidSnapshot(
                    "snapshot contains an unsupported memory writer".into(),
                ));
            }
        }
        let state: MicrovmState =
            serde_json::from_value(value).map_err(crate::snapshot::PersistError::from)?;
        state.validate_for_restore(self.vm_config.vcpu_count)?;
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
        if let Some(block) = &state.device_states.block {
            self.device_manager.block_manager.restore_state(block, ())?;
        }
        if let Some(net) = &state.device_states.virtio_net {
            self.device_manager.net_manager.restore_state(net, ())?;
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
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;
    use std::time::{Duration, Instant};
    use vm_memory::GuestMemory;
    use vmm_sys_util::tempfile::TempFile;

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

    fn configure_disk(vm: &mut Vm, path: &std::path::Path) {
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
        let mut vm = super::super::tests::create_vm_instance();
        let real = RealVcpuExecution::new(vm.vm_fd.clone());
        let config = VmConfigInfo {
            vcpu_count: 1,
            max_vcpu_count: 1,
            mem_size_mib: 16,
            mem_type: "shmem".to_owned(),
            cpu_pm: "off".to_owned(),
            ..Default::default()
        };
        vm.set_vm_config(config);
        if let Some(path) = disk {
            configure_disk(&mut vm, path);
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
            .save_microvm(state.as_path(), memory.as_path())
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
        let mut vm = super::super::tests::create_vm_instance();
        vm.set_vm_config(VmConfigInfo {
            mem_size_mib: 8192,
            mem_type: "shmem".into(),
            ..Default::default()
        });
        vm.init_guest_memory().unwrap();
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
}
