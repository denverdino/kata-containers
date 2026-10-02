// SPDX-License-Identifier: Apache-2.0

//! Complete device-set barrier for the qualified MMIO block/net profile.

use super::blk_dev_mgr::BlockDeviceType;
use super::net_dev_mgr::Backend;
use super::{DbsMmioV2Device, DeviceManager};
use crate::address_space_manager::GuestAddressSpaceImpl;
use crate::config_manager::ConfigItem;
use dbs_device::DeviceIo;
use dbs_virtio_devices::block::Block;
use dbs_virtio_devices::capture::{
    CaptureGeneration, CaptureResult, WorkerAck, WorkerCaptureControl,
};
use dbs_virtio_devices::net::{Net, NetCaptureControl};
use std::collections::BTreeMap;
use std::sync::{Arc, TryLockError};
use std::time::Instant;

/// Whether capture failed before any hold was issued or requires VM teardown.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCaptureError {
    /// No worker hold was issued; the caller can undo its vCPU pause.
    #[error("capture rejected before device hold: {0}")]
    Rejected(String),
    /// A hold or release was issued without a complete consistency proof.
    #[error("capture consistency uncertain; VM teardown required: {0}")]
    Terminal(String),
}

type Result<T> = std::result::Result<T, DeviceCaptureError>;

fn validate_acks(
    expected: &BTreeMap<String, bool>,
    generation: CaptureGeneration,
    acks: &[WorkerAck],
) -> Result<()> {
    if acks.len() != expected.len() {
        return Err(DeviceCaptureError::Terminal(
            "incomplete worker acknowledgement set".to_string(),
        ));
    }
    let mut seen = BTreeMap::new();
    for ack in acks {
        if generation.0 == 0
            || ack.generation != generation.0
            || ack.pending_io != 0
            || ack.memory_writers != 0
            || expected.get(&ack.device_id) != Some(&ack.flush_completed)
            || seen.insert(&ack.device_id, ()).is_some()
        {
            return Err(DeviceCaptureError::Terminal(format!(
                "invalid acknowledgement from {}",
                ack.device_id
            )));
        }
    }
    Ok(())
}

enum CaptureControl {
    Block(WorkerCaptureControl),
    Net(NetCaptureControl),
}

struct CaptureTarget {
    id: String,
    flush_required: bool,
    control: CaptureControl,
}

pub(super) struct DeviceCaptureSession {
    generation: CaptureGeneration,
    targets: Vec<CaptureTarget>,
    confirmed: bool,
}

impl CaptureTarget {
    fn hold(&self, generation: CaptureGeneration, deadline: Instant) -> CaptureResult<WorkerAck> {
        match &self.control {
            CaptureControl::Block(control) => control.request_hold(generation, deadline),
            CaptureControl::Net(control) => control.request_hold(generation, deadline),
        }
    }

    fn resume(&self, generation: CaptureGeneration, deadline: Instant) -> CaptureResult<()> {
        match &self.control {
            CaptureControl::Block(control) => control.resume(generation, deadline),
            CaptureControl::Net(control) => control.resume_capture(generation, deadline),
        }
    }
}

// Clone controls under the transport lock, then drop that lock before any wait.
fn device_control<D: 'static, T>(
    device: &Arc<dyn DeviceIo>,
    deadline: Instant,
    get: impl FnOnce(&D) -> CaptureResult<T>,
) -> Result<T> {
    let transport = device
        .as_any()
        .downcast_ref::<DbsMmioV2Device>()
        .ok_or_else(|| DeviceCaptureError::Rejected("unsupported device transport".to_string()))?;
    loop {
        if Instant::now() >= deadline {
            return Err(DeviceCaptureError::Rejected(
                "device control deadline expired".to_string(),
            ));
        }
        match transport.try_state() {
            Ok(mut guard) => {
                let inner = guard
                    .get_inner_device_mut()
                    .as_any_mut()
                    .downcast_mut::<D>()
                    .ok_or_else(|| {
                        DeviceCaptureError::Rejected("unsupported inner device".to_string())
                    })?;
                return get(inner).map_err(|e| DeviceCaptureError::Rejected(e.to_string()));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(DeviceCaptureError::Rejected(
                    "device lock poisoned".to_string(),
                ))
            }
            Err(TryLockError::WouldBlock) => std::thread::yield_now(),
        }
    }
}

fn hold_targets(
    targets: &[CaptureTarget],
    generation: CaptureGeneration,
    deadline: Instant,
) -> Result<Vec<WorkerAck>> {
    let mut expected = BTreeMap::new();
    for target in targets {
        if expected
            .insert(target.id.clone(), target.flush_required)
            .is_some()
        {
            return Err(DeviceCaptureError::Rejected(
                "duplicate configured worker identity".to_string(),
            ));
        }
    }
    let mut acks = Vec::with_capacity(targets.len());
    for target in targets {
        // Even a timed-out first request may have reached its worker. There is
        // no safe implicit rollback: the VMM must tear down on any such error.
        acks.push(
            target
                .hold(generation, deadline)
                .map_err(|e| DeviceCaptureError::Terminal(format!("{}: {e}", target.id)))?,
        );
    }
    validate_acks(&expected, generation, &acks)?;
    Ok(acks)
}

impl DeviceManager {
    /// Validate every live control before a caller pauses any vCPU.
    pub(crate) fn preflight_capture(&self, deadline: Instant) -> Result<()> {
        self.capture_targets(deadline).map(|_| ())
    }

    /// Arm all fresh MMIO devices before any activation is replayed.
    pub(crate) fn arm_capture_restore(&mut self, generation: CaptureGeneration) -> Result<()> {
        for info in self.block_manager.iter() {
            let device = info
                .device
                .as_ref()
                .ok_or_else(|| DeviceCaptureError::Rejected("unattached block".into()))?;
            super::persist::arm_device_capture(device, generation)
                .map_err(|e| DeviceCaptureError::Rejected(e.to_string()))?;
        }
        for info in self.net_manager.info_list.iter() {
            let device = info
                .device
                .as_ref()
                .ok_or_else(|| DeviceCaptureError::Rejected("unattached net".into()))?;
            super::persist::arm_device_capture(device, generation)
                .map_err(|e| DeviceCaptureError::Rejected(e.to_string()))?;
        }
        Ok(())
    }

    pub(crate) fn validate_capture_profile(&self) -> Result<()> {
        #[cfg(feature = "virtio-vsock")]
        if !self.vsock_manager.info_list.is_empty() {
            return Err(DeviceCaptureError::Rejected(
                "virtio-vsock memory writer is unsupported".to_string(),
            ));
        }
        #[cfg(any(feature = "virtio-fs", feature = "vhost-user-fs"))]
        if !self
            .fs_manager
            .try_lock()
            .map_err(|_| DeviceCaptureError::Rejected("fs inventory unavailable".to_string()))?
            .info_list
            .is_empty()
        {
            return Err(DeviceCaptureError::Rejected(
                "virtio-fs memory writer is unsupported".to_string(),
            ));
        }
        #[cfg(feature = "virtio-mem")]
        if !self.mem_manager.info_list.is_empty() {
            return Err(DeviceCaptureError::Rejected(
                "virtio-mem memory writer is unsupported".to_string(),
            ));
        }
        #[cfg(feature = "virtio-balloon")]
        if !self.balloon_manager.info_list.is_empty() {
            return Err(DeviceCaptureError::Rejected(
                "virtio-balloon memory writer is unsupported".to_string(),
            ));
        }
        #[cfg(feature = "virtio-rng")]
        if !self.rng_manager.info_list.is_empty() {
            return Err(DeviceCaptureError::Rejected(
                "virtio-rng memory writer is unsupported".to_string(),
            ));
        }
        #[cfg(feature = "host-device")]
        if !self
            .vfio_manager
            .try_lock()
            .map_err(|_| DeviceCaptureError::Rejected("VFIO inventory unavailable".to_string()))?
            .info_list
            .is_empty()
        {
            return Err(DeviceCaptureError::Rejected(
                "VFIO DMA writer is unsupported".to_string(),
            ));
        }

        for info in self.block_manager.iter() {
            let config = &info.config;
            if config.device_type != BlockDeviceType::RawBlock
                || config.drive_id.is_empty()
                || config.num_queues == 0
                || config.use_pci_bus == Some(true)
            {
                return Err(DeviceCaptureError::Rejected(
                    "unsupported block device profile".into(),
                ));
            }
        }
        for info in self.net_manager.info_list.iter() {
            if !matches!(info.config.backend, Backend::Virtio(_))
                || info.config.id().is_empty()
                || info.config.num_queues() != 2
            {
                return Err(DeviceCaptureError::Rejected(
                    "unsupported network device profile".into(),
                ));
            }
        }
        Ok(())
    }

    fn capture_targets(&self, deadline: Instant) -> Result<Vec<CaptureTarget>> {
        self.validate_capture_profile()?;
        let mut targets = Vec::new();
        for info in self.block_manager.iter() {
            let config = &info.config;
            if config.device_type != BlockDeviceType::RawBlock
                || config.drive_id.is_empty()
                || config.num_queues == 0
                || config.use_pci_bus == Some(true)
            {
                return Err(DeviceCaptureError::Rejected(
                    "unsupported block device profile".to_string(),
                ));
            }
            let device = info.device.as_ref().ok_or_else(|| {
                DeviceCaptureError::Rejected(format!("unattached block {}", config.drive_id))
            })?;
            let controls = device_control::<Block<GuestAddressSpaceImpl>, _>(
                device,
                deadline,
                Block::capture_controls,
            )?;
            if controls.len() != config.num_queues {
                return Err(DeviceCaptureError::Rejected(
                    "block worker count disagrees with configuration".to_string(),
                ));
            }
            for (queue, control) in controls.into_iter().enumerate() {
                targets.push(CaptureTarget {
                    id: format!("block:{}/q{queue}", config.drive_id),
                    flush_required: true,
                    control: CaptureControl::Block(control),
                });
            }
        }
        for info in self.net_manager.info_list.iter() {
            if !matches!(info.config.backend, Backend::Virtio(_))
                || info.config.id().is_empty()
                || info.config.num_queues() != 2
            {
                return Err(DeviceCaptureError::Rejected(
                    "unsupported network device profile".to_string(),
                ));
            }
            let device = info.device.as_ref().ok_or_else(|| {
                DeviceCaptureError::Rejected(format!("unattached net {}", info.config.id()))
            })?;
            let control = device_control::<Net<GuestAddressSpaceImpl>, _>(
                device,
                deadline,
                Net::capture_control,
            )?;
            targets.push(CaptureTarget {
                id: format!("net:{}", info.config.id()),
                flush_required: false,
                control: CaptureControl::Net(control),
            });
        }
        Ok(targets)
    }

    /// Freeze every configured supported device after vCPUs have parked.
    pub fn begin_capture(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> Result<Vec<WorkerAck>> {
        if self.capture_session.is_some() {
            return Err(DeviceCaptureError::Terminal(
                "capture already active".to_string(),
            ));
        }
        if generation.0 == 0 || Instant::now() >= deadline {
            return Err(DeviceCaptureError::Rejected(
                "invalid capture generation or deadline".to_string(),
            ));
        }
        let targets = self.capture_targets(deadline)?;
        self.capture_session = Some(DeviceCaptureSession {
            generation,
            targets,
            confirmed: false,
        });
        let session = self.capture_session.as_mut().unwrap();
        let report = hold_targets(&session.targets, generation, deadline)?;
        session.confirmed = true;
        Ok(report)
    }

    /// Resume requires confirmation from every worker in the same device set.
    pub fn end_capture(&mut self, generation: CaptureGeneration, deadline: Instant) -> Result<()> {
        if generation.0 == 0 || Instant::now() >= deadline {
            return Err(DeviceCaptureError::Terminal(
                "invalid release generation or deadline".to_string(),
            ));
        }
        let session = self.capture_session.as_ref().ok_or_else(|| {
            DeviceCaptureError::Terminal("no capture session to release".to_string())
        })?;
        if session.generation != generation || !session.confirmed {
            return Err(DeviceCaptureError::Terminal(
                "capture release lacks a confirmed matching session".to_string(),
            ));
        }
        for target in &session.targets {
            target
                .resume(generation, deadline)
                .map_err(|e| DeviceCaptureError::Terminal(format!("{}: {e}", target.id)))?;
        }
        self.capture_session = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_manager::blk_dev_mgr::{BlockDeviceConfigInfo, BlockDeviceType};
    use crate::device_manager::net_dev_mgr::NetworkInterfaceConfig;
    use crate::device_manager::DeviceOpContext;
    use std::time::Duration;

    #[cfg(not(feature = "atomic-guest-memory"))]
    static NEXT_TAP: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

    #[cfg(not(feature = "atomic-guest-memory"))]
    fn active_net(
        manager: &mut DeviceManager,
        epoll: &dbs_utils::epoll_manager::EpollManager,
        id: &str,
    ) -> (
        crate::address_space_manager::GuestAddressSpaceImpl,
        Arc<vmm_sys_util::eventfd::EventFd>,
        Arc<dyn DeviceIo>,
    ) {
        use crate::config_manager::DeviceConfigInfo;
        use crate::device_manager::net_dev_mgr::VirtioConfig;
        use dbs_device::resources::DeviceResources;
        use dbs_interrupt::NoopNotifier;
        use dbs_utils::net::Tap;
        use dbs_virtio_devices::{VirtioDevice, VirtioDeviceConfig, VirtioQueueConfig};
        use virtio_queue::{QueueSync, QueueT};
        use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let address_space = super::super::tests::create_address_space();
        let mut queues = Vec::new();
        for index in 0..2 {
            let base = 0x1000 + index as u32 * 0x1000;
            let mut queue = VirtioQueueConfig::<QueueSync>::create(16, index).unwrap();
            queue.queue.set_size(16);
            queue.queue.set_desc_table_address(Some(base), Some(0));
            queue
                .queue
                .set_avail_ring_address(Some(base + 0x200), Some(0));
            queue
                .queue
                .set_used_ring_address(Some(base + 0x300), Some(0));
            queue.queue.set_ready(true);
            queues.push(queue);
        }
        // One saved TX descriptor. RX has no available buffers.
        mem.write_obj(0x3000u64, GuestAddress(0x2000)).unwrap();
        mem.write_obj(64u32, GuestAddress(0x2008)).unwrap();
        mem.write_obj(1u16, GuestAddress(0x2202)).unwrap();
        let tx_event = queues[1].eventfd.clone();
        let config = VirtioDeviceConfig::<GuestAddressSpaceImpl>::new(
            mem.clone(),
            address_space.clone(),
            manager.vm_fd.clone(),
            DeviceResources::new(),
            queues,
            None,
            Arc::new(NoopNotifier::new()),
        );
        let tap_name = format!(
            "cap-{id}-{}",
            NEXT_TAP.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let tap = Tap::open_named(&tap_name, false).unwrap();
        let mut net = Net::new_with_tap(
            tap,
            None,
            Arc::new(vec![16, 16]),
            epoll.clone(),
            None,
            None,
            false,
        )
        .unwrap();
        net.set_capture_id(format!("net:{id}")).unwrap();
        net.activate(config).unwrap();
        let mut context = DeviceOpContext::new(
            Some(epoll.clone()),
            manager,
            Some(mem.clone()),
            Some(address_space),
            false,
            None,
            manager.shared_info.clone(),
        );
        let device =
            DeviceManager::create_mmio_virtio_device(Box::new(net), &mut context, false, false)
                .unwrap();
        let config = NetworkInterfaceConfig {
            backend: Backend::Virtio(VirtioConfig {
                iface_id: id.to_string(),
                host_dev_name: tap_name,
                ..Default::default()
            }),
            queue_size: Some(16),
            ..Default::default()
        };
        manager
            .net_manager
            .info_list
            .push(DeviceConfigInfo::new_with_device(
                config,
                Some(device.clone()),
            ));
        (mem, tx_event, device)
    }

    #[cfg(not(feature = "atomic-guest-memory"))]
    #[test]
    fn capture_manager_controls_real_activated_devices() {
        use vm_memory::{Bytes, GuestAddress};
        let epoll = dbs_utils::epoll_manager::EpollManager::default();
        let mut manager = DeviceManager::new_test_mgr();
        manager.vm_fd.create_irq_chip().unwrap();
        let (mem0, tx0, _) = active_net(&mut manager, &epoll, "eth0");
        let (mem1, tx1, _) = active_net(&mut manager, &epoll, "eth1");
        let deadline = Instant::now() + Duration::from_secs(1);
        let acks = manager
            .begin_capture(CaptureGeneration(1), deadline)
            .unwrap();
        assert_eq!(
            acks.iter()
                .map(|ack| ack.device_id.as_str())
                .collect::<Vec<_>>(),
            ["net:eth0", "net:eth1"]
        );
        tx0.write(1).unwrap();
        tx1.write(1).unwrap();
        epoll.handle_events(0).unwrap();
        assert_eq!(mem0.read_obj::<u16>(GuestAddress(0x2302)).unwrap(), 0);
        assert_eq!(mem1.read_obj::<u16>(GuestAddress(0x2302)).unwrap(), 0);
        manager.end_capture(CaptureGeneration(1), deadline).unwrap();
        epoll.handle_events(0).unwrap();
        assert_eq!(mem0.read_obj::<u16>(GuestAddress(0x2302)).unwrap(), 1);
        assert_eq!(mem1.read_obj::<u16>(GuestAddress(0x2302)).unwrap(), 1);
    }

    #[cfg(not(feature = "atomic-guest-memory"))]
    #[test]
    fn capture_release_cannot_forget_previously_held_devices() {
        use vm_memory::{Bytes, GuestAddress};
        let epoll = dbs_utils::epoll_manager::EpollManager::default();
        let mut manager = DeviceManager::new_test_mgr();
        manager.vm_fd.create_irq_chip().unwrap();
        let (mem, tx, _) = active_net(&mut manager, &epoll, "eth0");
        let deadline = Instant::now() + Duration::from_secs(1);
        manager
            .begin_capture(CaptureGeneration(1), deadline)
            .unwrap();
        manager.net_manager.info_list = crate::config_manager::DeviceConfigInfos::new();
        let released = manager.end_capture(CaptureGeneration(1), deadline);
        tx.write(1).unwrap();
        epoll.handle_events(0).unwrap();
        match released {
            Ok(()) => assert_eq!(mem.read_obj::<u16>(GuestAddress(0x2302)).unwrap(), 1),
            Err(DeviceCaptureError::Terminal(_)) => {}
            Err(other) => panic!("release cannot be a pre-hold rejection: {}", other),
        }
    }

    #[cfg(not(feature = "atomic-guest-memory"))]
    #[test]
    fn capture_partial_ack_requires_confirmed_release_or_teardown() {
        use vm_memory::{Bytes, GuestAddress};
        let epoll = dbs_utils::epoll_manager::EpollManager::default();
        let mut manager = DeviceManager::new_test_mgr();
        manager.vm_fd.create_irq_chip().unwrap();
        let (mem, tx, _) = active_net(&mut manager, &epoll, "eth0");
        let (_, _, second) = active_net(&mut manager, &epoll, "eth1");
        let deadline = Instant::now() + Duration::from_secs(1);
        let control = device_control::<Net<GuestAddressSpaceImpl>, _>(
            &second,
            deadline,
            Net::capture_control,
        )
        .unwrap();
        control
            .request_hold(CaptureGeneration(2), deadline)
            .unwrap();
        assert!(matches!(
            manager.begin_capture(CaptureGeneration(1), deadline),
            Err(DeviceCaptureError::Terminal(_))
        ));
        tx.write(1).unwrap();
        epoll.handle_events(0).unwrap();
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x2302)).unwrap(), 0);
        // A wrong-generation release cannot establish that every device resumed.
        assert!(matches!(
            manager.end_capture(CaptureGeneration(1), deadline),
            Err(DeviceCaptureError::Terminal(_))
        ));
        // This test tears down the entire manager/event loop, never resumes vCPUs.
        drop(manager);
        drop(epoll);
    }

    #[cfg(not(feature = "atomic-guest-memory"))]
    #[test]
    #[cfg(feature = "virtio-rng")]
    fn capture_rejects_rng_before_holding_active_net() {
        use crate::config_manager::DeviceConfigInfo;
        use crate::device_manager::rng_dev_mgr::RngDeviceConfigInfo;
        use vm_memory::{Bytes, GuestAddress};
        let epoll = dbs_utils::epoll_manager::EpollManager::default();
        let mut manager = DeviceManager::new_test_mgr();
        manager.vm_fd.create_irq_chip().unwrap();
        let (mem, tx, _) = active_net(&mut manager, &epoll, "eth0");
        manager
            .rng_manager
            .info_list
            .push(DeviceConfigInfo::new(RngDeviceConfigInfo {
                src: "/dev/urandom".to_string(),
                use_shared_irq: None,
                use_generic_irq: None,
            }));
        assert!(
            matches!(manager.begin_capture(CaptureGeneration(1), Instant::now() + Duration::from_secs(1)), Err(DeviceCaptureError::Rejected(message)) if message.contains("virtio-rng"))
        );
        tx.write(1).unwrap();
        epoll.handle_events(0).unwrap();
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x2302)).unwrap(), 1);
    }

    #[cfg(not(feature = "atomic-guest-memory"))]
    #[test]
    fn capture_transport_lock_obeys_deadline_before_any_hold() {
        let epoll = dbs_utils::epoll_manager::EpollManager::default();
        let mut manager = DeviceManager::new_test_mgr();
        manager.vm_fd.create_irq_chip().unwrap();
        let (_, _, device) = active_net(&mut manager, &epoll, "eth0");
        let transport = device.as_any().downcast_ref::<DbsMmioV2Device>().unwrap();
        let _guard = transport.state();
        assert!(matches!(
            manager.begin_capture(
                CaptureGeneration(1),
                Instant::now() + Duration::from_millis(1)
            ),
            Err(DeviceCaptureError::Rejected(_))
        ));
    }

    fn ack(id: &str, flush: bool) -> WorkerAck {
        WorkerAck {
            device_id: id.to_string(),
            generation: 1,
            pending_io: 0,
            memory_writers: 0,
            flush_completed: flush,
        }
    }

    #[test]
    fn capture_empty_set_still_requires_valid_generation_and_deadline() {
        let mut manager = DeviceManager::new_test_mgr();
        let future = Instant::now() + Duration::from_secs(1);
        assert!(matches!(
            manager.begin_capture(CaptureGeneration(0), future),
            Err(DeviceCaptureError::Rejected(_))
        ));
        assert!(matches!(
            manager.end_capture(CaptureGeneration(0), future),
            Err(DeviceCaptureError::Terminal(_))
        ));
        assert!(matches!(
            manager.end_capture(CaptureGeneration(1), Instant::now()),
            Err(DeviceCaptureError::Terminal(_))
        ));
    }

    #[test]
    fn capture_requires_every_configured_device_ack() {
        let expected = BTreeMap::from([
            ("block:root/q0".to_string(), true),
            ("net:eth0".to_string(), false),
        ]);
        let complete = vec![ack("block:root/q0", true), ack("net:eth0", false)];
        validate_acks(&expected, CaptureGeneration(1), &complete).unwrap();
        assert!(matches!(
            validate_acks(&expected, CaptureGeneration(1), &complete[..1]),
            Err(DeviceCaptureError::Terminal(_))
        ));
        let mut wrong = complete.clone();
        wrong[1].generation = 2;
        assert!(validate_acks(&expected, CaptureGeneration(1), &wrong).is_err());
        wrong[1] = complete[0].clone();
        assert!(validate_acks(&expected, CaptureGeneration(1), &wrong).is_err());
        wrong = complete.clone();
        wrong[0].pending_io = 1;
        assert!(validate_acks(&expected, CaptureGeneration(1), &wrong).is_err());
        wrong = complete.clone();
        wrong[1].memory_writers = 1;
        assert!(validate_acks(&expected, CaptureGeneration(1), &wrong).is_err());
        wrong = complete.clone();
        wrong[0].flush_completed = false;
        assert!(validate_acks(&expected, CaptureGeneration(1), &wrong).is_err());
    }

    #[test]
    fn capture_configured_but_unattached_net_cannot_be_empty_success() {
        let mut manager = DeviceManager::new_test_mgr();
        manager
            .net_manager
            .info_list
            .insert_or_update(&NetworkInterfaceConfig::default())
            .unwrap();
        assert!(matches!(
            manager.begin_capture(
                CaptureGeneration(1),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(DeviceCaptureError::Rejected(_))
        ));
    }

    #[test]
    fn capture_rejects_unsupported_memory_writer() {
        let mut vm = crate::vm::tests::create_vm_instance();
        let context = DeviceOpContext::create_boot_ctx(&vm, None);
        let config = BlockDeviceConfigInfo {
            drive_id: "external-dma".to_string(),
            device_type: BlockDeviceType::Spdk,
            ..Default::default()
        };
        let (sender, _) = std::sync::mpsc::channel();
        vm.device_manager_mut()
            .block_manager
            .insert_device(context, config, sender)
            .unwrap();
        assert!(matches!(
            vm.device_manager_mut().begin_capture(
                CaptureGeneration(1),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(DeviceCaptureError::Rejected(_))
        ));
    }
}
