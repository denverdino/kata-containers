// Copyright 2019-2020 Alibaba Cloud. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::any::Any;
use std::collections::HashMap;
use std::io::{Seek, SeekFrom};
use std::marker::PhantomData;
use std::sync::{mpsc, Arc};
use std::thread;

use dbs_device::resources::ResourceConstraint;
use dbs_utils::{
    epoll_manager::{EpollManager, SubscriberId},
    rate_limiter::{BucketUpdate, RateLimiter},
};
use log::{debug, error, info, warn};
use virtio_bindings::bindings::virtio_blk::*;
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1};
use virtio_queue::QueueT;
use vm_memory::GuestMemoryRegion;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::capture::{
    CaptureGate, CaptureGeneration, CaptureResult, WorkerAck, WorkerCaptureControl,
};
use crate::{
    ActivateError, ActivateResult, ConfigResult, DbsGuestAddressSpace, Error, Result, VirtioDevice,
    VirtioDeviceConfig, VirtioDeviceInfo, TYPE_BLOCK,
};

use super::{
    BlockEpollHandler, InnerBlockEpollHandler, KillEvent, Ufile, BLK_DRIVER_NAME, SECTOR_SHIFT,
    SECTOR_SIZE,
};

/// Supported fields in the configuration space:
/// - 64-bit disk size
/// - 32-bit size max
/// - 32-bit seg max
/// - 16-bit num_queues at offset 34
const CONFIG_SPACE_SIZE: usize = 64;

/// Max segments in a data request.
const CONFIG_MAX_SEG: u32 = 16;

fn build_device_id(disk_image: &dyn Ufile) -> Vec<u8> {
    let mut default_disk_image_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
    match disk_image.get_device_id() {
        Err(_) => warn!("Could not generate device id. We'll use a default."),
        Ok(m) => {
            // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
            // This will also zero out any leftover bytes.
            let disk_id = m.as_bytes();
            let bytes_to_copy = std::cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
            default_disk_image_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
        }
    }
    default_disk_image_id
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block<AS: DbsGuestAddressSpace> {
    pub(crate) device_info: VirtioDeviceInfo,
    disk_images: Vec<Box<dyn Ufile>>,
    rate_limiters: Vec<RateLimiter>,
    queue_sizes: Arc<Vec<u16>>,
    subscriber_id: Option<SubscriberId>,
    kill_evts: Vec<EventFd>,
    evt_senders: Vec<mpsc::Sender<KillEvent>>,
    epoll_threads: Vec<thread::JoinHandle<()>>,
    capture_controls: Vec<WorkerCaptureControl>,
    capture_id: String,
    phantom: PhantomData<AS>,
}

impl<AS: DbsGuestAddressSpace> Block<AS> {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(
        mut disk_images: Vec<Box<dyn Ufile>>,
        is_disk_read_only: bool,
        sparse: bool,
        queue_sizes: Arc<Vec<u16>>,
        epoll_mgr: EpollManager,
        rate_limiters: Vec<RateLimiter>,
        f_access_platform: bool,
    ) -> Result<Self> {
        let num_queues = disk_images.len();

        if num_queues == 0 {
            return Err(Error::InvalidInput);
        }

        let disk_image = &mut disk_images[0];

        let disk_size = disk_image.seek(SeekFrom::End(0)).map_err(Error::IOError)?;
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;
        avail_features |= 1u64 << VIRTIO_BLK_F_SIZE_MAX;
        avail_features |= 1u64 << VIRTIO_BLK_F_SEG_MAX;

        if f_access_platform {
            avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        if num_queues > 1 {
            avail_features |= 1u64 << VIRTIO_BLK_F_MQ;
        }

        if sparse {
            avail_features |= 1u64 << VIRTIO_BLK_F_DISCARD;
        }

        let config_space = Self::build_config_space(
            disk_size,
            disk_image.get_max_size(),
            num_queues as u16,
            sparse,
        );

        Ok(Block {
            device_info: VirtioDeviceInfo::new(
                BLK_DRIVER_NAME.to_string(),
                avail_features,
                queue_sizes.clone(),
                config_space,
                epoll_mgr,
            ),
            disk_images,
            rate_limiters,
            queue_sizes,
            subscriber_id: None,
            phantom: PhantomData,
            evt_senders: Vec::with_capacity(num_queues),
            kill_evts: Vec::with_capacity(num_queues),
            epoll_threads: Vec::with_capacity(num_queues),
            capture_controls: Vec::with_capacity(num_queues),
            capture_id: BLK_DRIVER_NAME.to_string(),
        })
    }

    /// Assign the machine's logical device ID before activation.
    pub fn set_capture_id(&mut self, id: String) -> Result<()> {
        if id.is_empty() || !self.capture_controls.is_empty() {
            return Err(Error::InvalidInput);
        }
        self.capture_id = id;
        Ok(())
    }

    /// Obtain worker controls without retaining the MMIO device lock while waiting.
    pub fn capture_controls(&self) -> CaptureResult<Vec<WorkerCaptureControl>> {
        if self.capture_controls.is_empty() || self.capture_controls.len() != self.queue_sizes.len()
        {
            return Err(crate::capture::CaptureError::Disconnected);
        }
        Ok(self.capture_controls.clone())
    }

    /// Hold all queues without retaining a queue/device lock while waiting.
    pub fn request_hold(
        &self,
        generation: CaptureGeneration,
        deadline: std::time::Instant,
    ) -> CaptureResult<Vec<WorkerAck>> {
        if self.capture_controls.is_empty() || self.capture_controls.len() != self.queue_sizes.len()
        {
            return Err(crate::capture::CaptureError::Disconnected);
        }
        self.capture_controls
            .iter()
            .map(|worker| worker.request_hold(generation, deadline))
            .collect()
    }

    /// Release every queue's barrier; the caller owns partial-failure recovery.
    pub fn resume_capture(
        &self,
        generation: CaptureGeneration,
        deadline: std::time::Instant,
    ) -> CaptureResult<()> {
        if self.capture_controls.is_empty() || self.capture_controls.len() != self.queue_sizes.len()
        {
            return Err(crate::capture::CaptureError::Disconnected);
        }
        for worker in &self.capture_controls {
            worker.resume(generation, deadline)?;
        }
        Ok(())
    }

    fn build_config_space(disk_size: u64, max_size: u32, num_queues: u16, sparse: bool) -> Vec<u8> {
        // The disk size field of the configuration space, which uses the first two words.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        // The config space is little endian.
        let mut config = Vec::with_capacity(CONFIG_SPACE_SIZE);
        let num_sectors = disk_size >> SECTOR_SHIFT;
        for i in 0..8 {
            config.push((num_sectors >> (8 * i)) as u8);
        }

        // The max_size field of the configuration space.
        for i in 0..4 {
            config.push((max_size >> (8 * i)) as u8);
        }

        // The max_seg field of the configuration space.
        let max_segs = CONFIG_MAX_SEG;
        for i in 0..4 {
            config.push((max_segs >> (8 * i)) as u8);
        }

        for _i in 0..18 {
            config.push(0_u8);
        }

        for i in 0..2 {
            config.push((num_queues >> (8 * i)) as u8);
        }

        let (max_discard_sectors, max_discard_seg, discard_sector_alignment) =
            if sparse { (u32::MAX, 1, 1) } else { (0, 0, 0) };
        for i in 0..4 {
            config.push((max_discard_sectors >> (8 * i)) as u8);
        }
        for i in 0..4 {
            config.push((max_discard_seg >> (8 * i)) as u8);
        }
        for i in 0..4 {
            config.push((discard_sector_alignment >> (8 * i)) as u8);
        }

        config.resize(CONFIG_SPACE_SIZE, 0);
        config
    }

    pub fn set_patch_rate_limiters(&self, bytes: BucketUpdate, ops: BucketUpdate) -> Result<()> {
        if self.evt_senders.is_empty()
            || self.kill_evts.is_empty()
            || self.evt_senders.len() != self.kill_evts.len()
        {
            error!("virtio-blk: failed to establish channel to send rate-limiter patch data");
            return Err(Error::InternalError);
        }

        for sender in self.evt_senders.iter() {
            if sender
                .send(KillEvent::BucketUpdate(bytes.clone(), ops.clone()))
                .is_err()
            {
                error!("virtio-blk: failed to send rate-limiter patch data");
                return Err(Error::InternalError);
            }
        }

        for kill_evt in self.kill_evts.iter() {
            if let Err(e) = kill_evt.write(1) {
                error!("virtio-blk: failed to write rate-limiter patch event {e:?}");
                return Err(Error::InternalError);
            }
        }

        Ok(())
    }
}

impl<'a, AS: DbsGuestAddressSpace> crate::persist::VirtioDevicePersist<'a> for Block<AS> {
    type State = crate::persist::VirtioDeviceInfoState;
    type SaveArgs = ();
    type RestoreArgs = ();
    type Error = crate::Error;

    /// Capture the guest-negotiated state of this device.
    fn save_state(&mut self, _args: ()) -> crate::Result<Self::State> {
        Ok(self.device_info.save_state())
    }

    /// Restore the guest-negotiated state of this device.
    ///
    /// The device must have been re-created with the same configuration and
    /// must not have been activated yet.
    fn restore_state(&mut self, state: &Self::State, _args: ()) -> crate::Result<()> {
        self.device_info.restore_state(state)
    }
}

impl<AS, Q, R> VirtioDevice<AS, Q, R> for Block<AS>
where
    AS: DbsGuestAddressSpace,
    Q: QueueT + Send + 'static,
    R: GuestMemoryRegion + Sync + Send + 'static,
{
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn get_avail_features(&self, page: u32) -> u32 {
        self.device_info.get_avail_features(page)
    }

    fn set_acked_features(&mut self, page: u32, value: u32) {
        self.device_info.set_acked_features(page, value)
    }

    fn read_config(&mut self, offset: u64, data: &mut [u8]) -> ConfigResult {
        self.device_info.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> ConfigResult {
        self.device_info.write_config(offset, data)
    }

    fn activate(&mut self, mut config: VirtioDeviceConfig<AS, Q, R>) -> ActivateResult {
        self.device_info.check_queue_sizes(&config.queues[..])?;

        if self.disk_images.len() != config.queues.len() {
            error!(
                "The disk images number: {} is not equal to queues number: {}",
                self.disk_images.len(),
                config.queues.len()
            );
            return Err(ActivateError::InternalError);
        }
        let mut kill_evts = Vec::with_capacity(self.queue_sizes.len());

        let mut i = 0;
        // first to reverse the queue's order, thus to make sure the following
        // pop queue got the right queue order.
        config.queues.reverse();
        while let Some(queue) = config.queues.pop() {
            let disk_image = self.disk_images.pop().unwrap();
            let disk_image_id = build_device_id(disk_image.as_ref());

            let data_desc_vec =
                vec![Vec::with_capacity(CONFIG_MAX_SEG as usize); self.queue_sizes[0] as usize];
            let iovecs_vec =
                vec![Vec::with_capacity(CONFIG_MAX_SEG as usize); self.queue_sizes[0] as usize];

            let rate_limiter = self.rate_limiters.pop().unwrap_or_default();

            let (evt_sender, evt_receiver) = mpsc::channel();
            self.evt_senders.push(evt_sender);

            let kill_evt = EventFd::new(EFD_NONBLOCK)?;
            let (capture_control, capture_receiver) =
                WorkerCaptureControl::new(kill_evt.try_clone()?);
            self.capture_controls.push(capture_control);

            let mut handler = Box::new(InnerBlockEpollHandler {
                rate_limiter,
                disk_image,
                disk_image_id,
                pending_req_map: HashMap::new(),
                data_desc_vec,
                iovecs_vec,
                evt_receiver,
                vm_as: config.vm_as.clone(),
                queue,
                kill_evt: kill_evt.try_clone().unwrap(),
                capture_receiver,
                capture: CaptureGate::new(format!("{}/q{i}", self.capture_id)),
            });

            kill_evts.push(kill_evt.try_clone().unwrap());
            self.kill_evts.push(kill_evt);

            thread::Builder::new()
                .name(format!("{}_q{}", "blk_iothread", i))
                .spawn(move || {
                    if let Err(e) = handler.run() {
                        error!("Error running worker: {e:?}");
                    }
                })
                .map(|thread| self.epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone the virtio-block epoll thread: {e}");
                    ActivateError::InternalError
                })?;

            i += 1;
        }
        let block_handler = Box::new(BlockEpollHandler {
            kill_evts,
            evt_senders: self.evt_senders.clone(),
            config,
        });

        // subscribe this handler for io drain.
        self.subscriber_id = Some(self.device_info.register_event_handler(block_handler));

        Ok(())
    }

    fn reset(&mut self) -> ActivateResult {
        Ok(())
    }

    fn remove(&mut self) {
        // if the subsriber_id is invalid, it has not been activated yet.
        if let Some(subscriber_id) = self.subscriber_id {
            // Remove BlockEpollHandler from event manager, so it could be dropped and the resources
            // could be freed, e.g. close disk_image, so vmm won't hold the backend file.
            match self.device_info.remove_event_handler(subscriber_id) {
                Ok(_) => debug!("virtio-blk: removed subscriber_id {subscriber_id:?}"),
                Err(e) => {
                    warn!("virtio-blk: failed to remove event handler: {e:?}");
                }
            }
        }

        for sender in self.evt_senders.iter() {
            if sender.send(KillEvent::Kill).is_err() {
                error!("virtio-blk: failed to send kill event to epoller thread");
            }
        }

        // notify the io threads handlers to terminate.
        for kill_evt in self.kill_evts.iter() {
            if let Err(e) = kill_evt.write(1) {
                error!("virtio-blk: failed to write kill event {e:?}");
            }
        }

        while let Some(thread) = self.epoll_threads.pop() {
            if let Err(e) = thread.join() {
                error!("virtio-blk: failed to reap the io threads: {e:?}");
            } else {
                info!("io thread got reaped.");
            }
        }

        self.subscriber_id = None;
    }

    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    ) {
        requests.push(ResourceConstraint::LegacyIrq { irq: None });
        if use_generic_irq {
            requests.push(ResourceConstraint::GenericIrq {
                size: (self.queue_sizes.len() + 1) as u32,
            });
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::time::{Duration, Instant};

    use dbs_device::resources::DeviceResources;
    use dbs_interrupt::NoopNotifier;
    use dbs_utils::rate_limiter::{TokenBucket, TokenType};
    use kvm_ioctls::Kvm;
    use test_utils::skip_if_kvm_unaccessable;
    use virtio_queue::QueueSync;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap};
    use vmm_sys_util::eventfd::EventFd;
    use vmm_sys_util::tempfile::TempFile;

    use crate::epoll_helper::*;
    use crate::tests::{create_address_space, VirtQueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::{Error as VirtioError, VirtioQueueConfig};

    use super::*;
    use crate::block::aio::Aio;
    use crate::block::*;
    use crate::capture::{
        CaptureError, CaptureGate, CaptureGeneration, WorkerCaptureControl, WorkerCommand,
    };

    pub(super) struct DummyFile {
        pub(super) device_id: Option<String>,
        pub(super) capacity: u64,
        pub(super) have_complete_io: bool,
        pub(super) max_size: u32,
        pub(super) flush_error: bool,
    }

    impl DummyFile {
        pub(super) fn new() -> Self {
            DummyFile {
                device_id: None,
                capacity: 0,
                have_complete_io: false,
                max_size: 0x100000,
                flush_error: false,
            }
        }
    }

    impl Read for DummyFile {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
    }

    impl Write for DummyFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.flush_error {
                Err(std::io::Error::other("test flush error"))
            } else {
                Ok(())
            }
        }
    }
    impl Seek for DummyFile {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }

    impl Ufile for DummyFile {
        fn sync_all(&mut self) -> io::Result<()> {
            self.flush()
        }

        fn get_capacity(&self) -> u64 {
            self.capacity
        }

        fn get_max_size(&self) -> u32 {
            self.max_size
        }

        fn get_device_id(&self) -> io::Result<String> {
            match &self.device_id {
                Some(id) => Ok(id.to_string()),
                None => Err(std::io::Error::other("dummy_error")),
            }
        }

        // std err
        fn get_data_evt_fd(&self) -> RawFd {
            2
        }

        fn io_read_submit(
            &mut self,
            _offset: i64,
            _iovecs: &mut Vec<IoDataDesc>,
            _aio_data: u16,
        ) -> io::Result<usize> {
            Ok(0)
        }

        fn io_write_submit(
            &mut self,
            _offset: i64,
            _iovecs: &mut Vec<IoDataDesc>,
            _aio_data: u16,
        ) -> io::Result<usize> {
            Ok(0)
        }

        fn punch_hole(&mut self, _offset: u64, _length: u64) -> io::Result<()> {
            Ok(())
        }

        fn io_complete(&mut self) -> io::Result<Vec<(u16, u32)>> {
            let mut v = Vec::new();
            if self.have_complete_io {
                v.push((0, 1));
            }
            Ok(v)
        }
    }

    #[test]
    fn test_block_build_device_id() {
        let device_id = "dummy_device_id";
        let mut file = DummyFile::new();
        file.device_id = Some(device_id.to_string());
        let disk_image: Box<dyn Ufile> = Box::new(file);
        let disk_id = build_device_id(disk_image.as_ref());
        assert_eq!(disk_id.len() as u32, VIRTIO_BLK_ID_BYTES);
        let disk_image: Box<dyn Ufile> = Box::new(DummyFile::new());
        let disk_id2 = build_device_id(disk_image.as_ref());
        assert_eq!(disk_id2.len() as u32, VIRTIO_BLK_ID_BYTES);
        assert_ne!(disk_id, disk_id2);
    }

    #[test]
    fn test_block_request_parse() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let mut data_descs = Vec::with_capacity(CONFIG_MAX_SEG as usize);

        assert!(vq.end().0 < 0x1000);

        vq.avail.ring(0).store(0);
        vq.avail.idx().store(1);

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // write only request type descriptor
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(0x1000))
                .unwrap();
            m.write_obj::<u64>(114, GuestAddress(0x1000 + 8)).unwrap();
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::UnexpectedWriteOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // chain too short; no status_desc
            vq.dtable(0).flags().store(0);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::DescriptorChainTooShort)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // chain too short; no data desc
            vq.dtable(0).flags().store(VIRTQ_DESC_F_NEXT);
            vq.dtable(1).set(0x2000, 0x1000, 0, 2);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::DescriptorChainTooShort)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // write only data for OUT
            vq.dtable(1)
                .flags()
                .store(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            vq.dtable(2).set(0x3000, 0, 0, 0);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::UnexpectedWriteOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // read only data for OUT
            m.write_obj::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1)
                .flags()
                .store(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::UnexpectedWriteOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // length too big data for OUT
            m.write_obj::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1).flags().store(VIRTQ_DESC_F_NEXT);
            vq.dtable(1).len().store(64);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::DescriptorLengthTooBig)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // read only data for IN
            m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1).flags().store(VIRTQ_DESC_F_NEXT);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::UnexpectedReadOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // length too big data for IN
            m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1)
                .flags()
                .store(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            vq.dtable(1).len().store(64);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::DescriptorLengthTooBig)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // data desc write only and request type is getDeviceId
            m.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1)
                .flags()
                .store(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::UnexpectedReadOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // data desc write only for discard
            m.write_obj::<u32>(VIRTIO_BLK_T_DISCARD, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1)
                .set(0x2000, 16, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::UnexpectedWriteOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // discard segment must be exactly one virtio_blk_discard_write_zeroes.
            m.write_obj::<u32>(VIRTIO_BLK_T_DISCARD, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1).set(0x2000, 8, VIRTQ_DESC_F_NEXT, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::DescriptorLengthTooSmall)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // max_discard_seg is one, so reject larger discard payloads.
            m.write_obj::<u32>(VIRTIO_BLK_T_DISCARD, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1).set(0x2000, 32, VIRTQ_DESC_F_NEXT, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::DescriptorLengthTooBig)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // status desc read only
            m.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1)
                .set(0x2000, 0x40, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).flags().store(0);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::UnexpectedReadOnlyDescriptor)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // status desc too small
            m.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, GuestAddress(0x1000))
                .unwrap();
            vq.dtable(1)
                .set(0x2000, 0x40, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).flags().store(VIRTQ_DESC_F_WRITE);
            vq.dtable(2).len().store(0);
            assert!(matches!(
                Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32),
                Err(Error::DescriptorLengthTooSmall)
            ));
        }

        {
            let mut q = vq.create_queue();
            data_descs.clear();
            // should be OK now
            vq.dtable(2).len().store(0x1000);
            let r = Request::parse(&mut q.pop_descriptor_chain(m).unwrap(), &mut data_descs, 32)
                .unwrap();

            assert_eq!(r.request_type, RequestType::GetDeviceID);
            assert_eq!(r.sector, 114);
            assert_eq!(data_descs[0].data_addr, 0x2000);
            assert_eq!(data_descs[0].data_len, 0x40);
            assert_eq!(r.status_addr, GuestAddress(0x3000));
        }
    }

    #[test]
    fn test_block_request_execute() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let mut data_descs = Vec::with_capacity(CONFIG_MAX_SEG as usize);
        assert!(vq.end().0 < 0x1000);
        vq.avail.ring(0).store(0);
        vq.avail.idx().store(1);

        let mut file = DummyFile::new();
        file.capacity = 4096;
        let mut disk: Box<dyn Ufile> = Box::new(file);
        let disk_id = build_device_id(disk.as_ref());

        {
            // RequestType::In
            let mut q = vq.create_queue();
            data_descs.clear();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();
            let req = Request::parse(
                &mut q.pop_descriptor_chain(m).unwrap(),
                &mut data_descs,
                0x100000,
            )
            .unwrap();
            assert!(req.execute(&mut disk, m, &data_descs, &disk_id).is_ok());
        }

        {
            // RequestType::Out
            let mut q = vq.create_queue();
            data_descs.clear();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1).set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(0x1000))
                .unwrap();
            let req = Request::parse(
                &mut q.pop_descriptor_chain(m).unwrap(),
                &mut data_descs,
                0x100000,
            )
            .unwrap();
            assert!(req.execute(&mut disk, m, &data_descs, &disk_id).is_ok());
        }

        {
            // RequestType::Flush
            let mut q = vq.create_queue();
            data_descs.clear();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1).set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, GuestAddress(0x1000))
                .unwrap();
            let req = Request::parse(
                &mut q.pop_descriptor_chain(m).unwrap(),
                &mut data_descs,
                0x100000,
            )
            .unwrap();
            assert!(req.execute(&mut disk, m, &data_descs, &disk_id).is_ok());
        }

        {
            // RequestType::GetDeviceID
            let mut q = vq.create_queue();
            data_descs.clear();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, GuestAddress(0x1000))
                .unwrap();
            let req = Request::parse(
                &mut q.pop_descriptor_chain(m).unwrap(),
                &mut data_descs,
                0x100000,
            )
            .unwrap();
            assert!(req.execute(&mut disk, m, &data_descs, &disk_id).is_ok());
        }

        {
            // RequestType::Discard
            let mut q = vq.create_queue();
            data_descs.clear();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1).set(0x2000, 16, VIRTQ_DESC_F_NEXT, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_DISCARD, GuestAddress(0x1000))
                .unwrap();
            m.write_obj::<u64>(1, GuestAddress(0x2000)).unwrap();
            m.write_obj::<u32>(2, GuestAddress(0x2008)).unwrap();
            let req = Request::parse(
                &mut q.pop_descriptor_chain(m).unwrap(),
                &mut data_descs,
                0x100000,
            )
            .unwrap();
            assert!(req.execute(&mut disk, m, &data_descs, &disk_id).is_ok());
        }

        {
            // RequestType::Discard rejects ranges past disk capacity.
            let mut q = vq.create_queue();
            data_descs.clear();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1).set(0x2000, 16, VIRTQ_DESC_F_NEXT, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_DISCARD, GuestAddress(0x1000))
                .unwrap();
            m.write_obj::<u64>(7, GuestAddress(0x2000)).unwrap();
            m.write_obj::<u32>(2, GuestAddress(0x2008)).unwrap();
            let req = Request::parse(
                &mut q.pop_descriptor_chain(m).unwrap(),
                &mut data_descs,
                0x100000,
            )
            .unwrap();
            assert!(matches!(
                req.execute(&mut disk, m, &data_descs, &disk_id),
                Err(ExecuteError::BadRequest(VirtioError::InvalidOffset))
            ));
        }

        {
            // RequestType::unsupport
            let mut q = vq.create_queue();
            data_descs.clear();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_GET_ID + 10, GuestAddress(0x1000))
                .unwrap();
            let req = Request::parse(
                &mut q.pop_descriptor_chain(m).unwrap(),
                &mut data_descs,
                0x100000,
            )
            .unwrap();
            match req.execute(&mut disk, m, &data_descs, &disk_id) {
                Err(ExecuteError::Unsupported(n)) => assert_eq!(n, VIRTIO_BLK_T_GET_ID + 10),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn test_block_request_update_status() {
        let m = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let vq = VirtQueue::new(GuestAddress(0), &m, 16);
        let mut data_descs = Vec::with_capacity(CONFIG_MAX_SEG as usize);
        assert!(vq.end().0 < 0x1000);
        vq.avail.ring(0).store(0);
        vq.avail.idx().store(1);
        let mut q = vq.create_queue();
        vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable(1)
            .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
        m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
            .unwrap();
        let req = Request::parse(
            &mut q.pop_descriptor_chain(m.as_ref()).unwrap(),
            &mut data_descs,
            0x100000,
        )
        .unwrap();
        req.update_status(m.as_ref(), 0);
    }

    #[test]
    fn test_block_request_check_capacity() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let mut data_descs = Vec::with_capacity(CONFIG_MAX_SEG as usize);
        assert!(vq.end().0 < 0x1000);
        vq.avail.ring(0).store(0);
        vq.avail.idx().store(1);

        let mut disk: Box<dyn Ufile> = Box::new(DummyFile::new());
        let disk_id = build_device_id(disk.as_ref());
        let mut q = vq.create_queue();
        vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable(1)
            .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
        m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
            .unwrap();
        let req = Request::parse(
            &mut q.pop_descriptor_chain(m).unwrap(),
            &mut data_descs,
            0x100000,
        )
        .unwrap();
        assert!(matches!(
            req.execute(&mut disk, m, &data_descs, &disk_id),
            Err(ExecuteError::BadRequest(VirtioError::InvalidOffset))
        ));

        let mut file = DummyFile::new();
        file.capacity = 4096;
        let mut disk: Box<dyn Ufile> = Box::new(file);
        let mut q = vq.create_queue();
        data_descs.clear();
        vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable(1)
            .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
        m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
            .unwrap();
        let req = Request::parse(
            &mut q.pop_descriptor_chain(m).unwrap(),
            &mut data_descs,
            0x100000,
        )
        .unwrap();
        assert!(req.check_capacity(&mut disk, &data_descs).is_ok());
    }

    #[test]
    fn test_block_virtio_device_normal() {
        let device_id = "dummy_device_id";
        let epoll_mgr = EpollManager::default();

        let mut file = DummyFile::new();
        println!("max size {}", file.max_size);
        file.device_id = Some(device_id.to_string());
        let disk_image: Box<dyn Ufile> = Box::new(file);
        let mut dev = Block::<Arc<GuestMemoryMmap>>::new(
            vec![disk_image],
            true,
            false,
            Arc::new(vec![128]),
            epoll_mgr,
            vec![],
            false,
        )
        .unwrap();

        assert_eq!(
            VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::device_type(&dev),
            TYPE_BLOCK
        );
        let queue_size = [128];
        assert_eq!(
            VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::queue_max_sizes(
                &dev
            ),
            &queue_size[..]
        );
        assert_eq!(
            VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::get_avail_features(&dev, 0),
            dev.device_info.get_avail_features(0)
        );
        assert_eq!(
            VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::get_avail_features(&dev, 1),
            dev.device_info.get_avail_features(1)
        );
        assert_eq!(
            VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::get_avail_features(&dev, 2),
            dev.device_info.get_avail_features(2)
        );
        let mut config: [u8; 1] = [0];
        VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::read_config(
            &mut dev,
            0,
            &mut config,
        )
        .unwrap();
        let config: [u8; 16] = [0; 16];
        VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::write_config(
            &mut dev, 0, &config,
        )
        .unwrap();
    }

    #[test]
    fn test_block_virtio_device_active() {
        skip_if_kvm_unaccessable!();
        let device_id = "dummy_device_id";
        let epoll_mgr = EpollManager::default();

        {
            // check_queue_sizes error
            let mut file = DummyFile::new();
            file.device_id = Some(device_id.to_string());
            let disk_image: Box<dyn Ufile> = Box::new(file);
            let mut dev = Block::<Arc<GuestMemoryMmap<()>>>::new(
                vec![disk_image],
                true,
                false,
                Arc::new(vec![128]),
                epoll_mgr.clone(),
                vec![],
                false,
            )
            .unwrap();

            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
            let queues = Vec::new();

            let kvm = Kvm::new().unwrap();
            let vm_fd = Arc::new(kvm.create_vm().unwrap());
            let resources = DeviceResources::new();
            let address_space = create_address_space();
            let config = VirtioDeviceConfig::<Arc<GuestMemoryMmap<()>>>::new(
                Arc::new(mem),
                address_space,
                vm_fd,
                resources,
                queues,
                None,
                Arc::new(NoopNotifier::new()),
            );

            assert!(matches!(
                dev.activate(config),
                Err(ActivateError::InvalidParam)
            ));
        }

        {
            // test no disk_image
            let mut file = DummyFile::new();
            file.device_id = Some(device_id.to_string());
            let disk_image: Box<dyn Ufile> = Box::new(file);
            let mut dev = Block::new(
                vec![disk_image],
                true,
                false,
                Arc::new(vec![128]),
                epoll_mgr.clone(),
                vec![],
                false,
            )
            .unwrap();
            dev.disk_images = vec![];

            let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
            let queues = vec![VirtioQueueConfig::<QueueSync>::create(256, 0).unwrap()];

            let kvm = Kvm::new().unwrap();
            let vm_fd = Arc::new(kvm.create_vm().unwrap());
            let resources = DeviceResources::new();
            let address_space = create_address_space();
            let config = VirtioDeviceConfig::<Arc<GuestMemoryMmap<()>>>::new(
                Arc::new(mem),
                address_space,
                vm_fd,
                resources,
                queues,
                None,
                Arc::new(NoopNotifier::new()),
            );

            assert!(matches!(
                dev.activate(config),
                Err(ActivateError::InternalError)
            ));
        }

        {
            // Ok
            let mut file = DummyFile::new();
            file.device_id = Some(device_id.to_string());
            let disk_image: Box<dyn Ufile> = Box::new(file);
            let mut dev = Block::new(
                vec![disk_image],
                true,
                false,
                Arc::new(vec![128]),
                epoll_mgr,
                vec![],
                false,
            )
            .unwrap();

            let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
            let queues = vec![VirtioQueueConfig::<QueueSync>::create(256, 0).unwrap()];

            let kvm = Kvm::new().unwrap();
            let vm_fd = Arc::new(kvm.create_vm().unwrap());
            let resources = DeviceResources::new();
            let address_space = create_address_space();
            let config = VirtioDeviceConfig::<Arc<GuestMemoryMmap<()>>>::new(
                Arc::new(mem),
                address_space,
                vm_fd,
                resources,
                queues,
                None,
                Arc::new(NoopNotifier::new()),
            );

            dev.activate(config).unwrap();
        }
    }

    #[test]
    fn test_block_set_patch_rate_limiters() {
        let device_id = "dummy_device_id";
        let epoll_mgr = EpollManager::default();
        let mut file = DummyFile::new();
        file.device_id = Some(device_id.to_string());
        let disk_image: Box<dyn Ufile> = Box::new(file);
        let mut dev = Block::<Arc<GuestMemoryMmap>>::new(
            vec![disk_image],
            true,
            false,
            Arc::new(vec![128]),
            epoll_mgr,
            vec![],
            false,
        )
        .unwrap();

        let (sender, _receiver) = mpsc::channel();
        dev.evt_senders = vec![sender];
        let event = EventFd::new(0).unwrap();
        dev.kill_evts = vec![event];

        assert!(dev
            .set_patch_rate_limiters(BucketUpdate::None, BucketUpdate::None)
            .is_ok());
    }

    fn get_block_epoll_handler_with_file(
        file: DummyFile,
    ) -> InnerBlockEpollHandler<Arc<GuestMemoryMmap>, QueueSync> {
        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), 0x10000)]).unwrap());
        let queue = VirtioQueueConfig::create(256, 0).unwrap();
        let rate_limiter = RateLimiter::default();
        let disk_image: Box<dyn Ufile> = Box::new(file);
        let disk_image_id = build_device_id(disk_image.as_ref());

        let data_desc_vec = vec![Vec::with_capacity(CONFIG_MAX_SEG as usize); 256];
        let iovecs_vec = vec![Vec::with_capacity(CONFIG_MAX_SEG as usize); 256];

        let (_, evt_receiver) = mpsc::channel();
        let (_, capture_receiver) = mpsc::channel();

        InnerBlockEpollHandler {
            disk_image,
            disk_image_id,
            rate_limiter,
            pending_req_map: HashMap::new(),
            data_desc_vec,
            iovecs_vec,

            kill_evt: EventFd::new(0).unwrap(),
            evt_receiver,
            capture_receiver,
            capture: CaptureGate::new("test-drive/q0".to_string()),

            vm_as: mem,
            queue,
        }
    }

    fn get_block_epoll_handler() -> InnerBlockEpollHandler<Arc<GuestMemoryMmap>, QueueSync> {
        let mut file = DummyFile::new();
        file.capacity = 0x100000;
        get_block_epoll_handler_with_file(file)
    }

    #[test]
    fn test_block_get_patch_rate_limiters() {
        let mut handler = get_block_epoll_handler();
        let tokenbucket = TokenBucket::new(1, 1, 4);

        handler.get_patch_rate_limiters(
            BucketUpdate::None,
            BucketUpdate::Update(tokenbucket.clone()),
        );
        assert_eq!(handler.rate_limiter.ops().unwrap(), &tokenbucket);
    }

    #[test]
    fn test_block_epoll_handler_handle_event() {
        let mut handler = get_block_epoll_handler();
        let mut helper = EpollHelper::new().unwrap();

        // test for QUEUE_AVAIL_EVENT
        let events = epoll::Event::new(epoll::Events::EPOLLIN, QUEUE_AVAIL_EVENT as u64);
        handler.handle_event(&mut helper, &events);
        handler.queue.generate_event().unwrap();
        handler.handle_event(&mut helper, &events);

        // test for RATE_LIMITER_EVENT
        let events = epoll::Event::new(epoll::Events::EPOLLIN, RATE_LIMITER_EVENT as u64);
        handler.handle_event(&mut helper, &events);

        // test for END_IO_EVENT
        let events = epoll::Event::new(epoll::Events::EPOLLIN, END_IO_EVENT as u64);
        handler.handle_event(&mut helper, &events);
    }

    #[test]
    #[should_panic]
    fn test_block_epoll_handler_handle_unknown_event() {
        let mut handler = get_block_epoll_handler();
        let mut helper = EpollHelper::new().unwrap();

        // test for unknown event
        let events = epoll::Event::new(epoll::Events::EPOLLIN, KILL_EVENT as u64 + 10);
        handler.handle_event(&mut helper, &events);
    }

    #[test]
    fn test_block_epoll_handler_process_queue() {
        {
            let mut file = DummyFile::new();
            file.capacity = 0x100000;
            // set disk max_size to 0 will cause Request parse error
            file.max_size = 0;
            let mut handler = get_block_epoll_handler_with_file(file);

            let m = &handler.vm_as.clone();
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            vq.avail.ring(0).store(0);
            vq.avail.idx().store(1);
            let q = vq.create_queue();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();

            handler.queue = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(handler.process_queue());
        }

        {
            // will cause check_capacity error
            let file = DummyFile::new();
            let mut handler = get_block_epoll_handler_with_file(file);
            let m = &handler.vm_as.clone();
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            vq.avail.ring(0).store(0);
            vq.avail.idx().store(1);
            let q = vq.create_queue();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();

            handler.queue = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(handler.process_queue());
            let err_info: u32 = handler.vm_as.read_obj(GuestAddress(0x3000)).unwrap();
            assert_eq!(err_info, VIRTIO_BLK_S_IOERR);
        }

        {
            // test io submit
            let mut file = DummyFile::new();
            file.capacity = 0x100000;
            let mut handler = get_block_epoll_handler_with_file(file);
            let m = &handler.vm_as.clone();
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            vq.avail.ring(0).store(0);
            vq.avail.idx().store(1);
            let q = vq.create_queue();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                .unwrap();

            handler.queue = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(!handler.process_queue());
            assert_eq!(handler.pending_req_map.len(), 1);
        }

        {
            // test for other execute type (not IN/OUT)
            let mut file = DummyFile::new();
            file.capacity = 0x100000;
            let mut handler = get_block_epoll_handler_with_file(file);
            let m = &handler.vm_as.clone();
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            vq.avail.ring(0).store(0);
            vq.avail.idx().store(1);
            let q = vq.create_queue();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, GuestAddress(0x1000))
                .unwrap();

            handler.queue = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(handler.process_queue());
            let err_info: u32 = handler.vm_as.read_obj(GuestAddress(0x3000)).unwrap();
            assert_eq!(err_info, VIRTIO_BLK_S_OK);
        }

        {
            // test for other execute type (not IN/OUT) : error
            let mut file = DummyFile::new();
            file.capacity = 0x100000;
            file.flush_error = true;
            let mut handler = get_block_epoll_handler_with_file(file);
            let m = &handler.vm_as.clone();
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            vq.avail.ring(0).store(0);
            vq.avail.idx().store(1);
            let q = vq.create_queue();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, GuestAddress(0x1000))
                .unwrap();

            handler.queue = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(handler.process_queue());
            let err_info: u32 = handler.vm_as.read_obj(GuestAddress(0x3000)).unwrap();
            assert_eq!(err_info, VIRTIO_BLK_S_IOERR);
        }

        {
            // test for other execute type (not IN/OUT) : non_supported
            let mut file = DummyFile::new();
            file.capacity = 0x100000;
            let mut handler = get_block_epoll_handler_with_file(file);
            let m = &handler.vm_as.clone();
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            vq.avail.ring(0).store(0);
            vq.avail.idx().store(1);
            let q = vq.create_queue();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_FLUSH + 10, GuestAddress(0x1000))
                .unwrap();

            handler.queue = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(handler.process_queue());
            let err_info: u32 = handler.vm_as.read_obj(GuestAddress(0x3000)).unwrap();
            assert_eq!(err_info, VIRTIO_BLK_S_UNSUPP);
        }

        {
            // test for rate limiter
            let mut file = DummyFile::new();
            file.capacity = 0x100000;
            let mut handler = get_block_epoll_handler_with_file(file);
            handler.rate_limiter = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
            handler.rate_limiter.consume(1, TokenType::Ops);
            let m = &handler.vm_as.clone();
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            vq.avail.ring(0).store(0);
            vq.avail.idx().store(1);
            let q = vq.create_queue();
            vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable(1)
                .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
            vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 1);
            m.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, GuestAddress(0x1000))
                .unwrap();

            handler.queue = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(!handler.process_queue());
            // test if rate limited
            assert!(handler.rate_limiter.is_blocked());
        }
    }

    fn capture_block_fixture() -> (
        InnerBlockEpollHandler<Arc<GuestMemoryMmap>, QueueSync>,
        WorkerCaptureControl,
    ) {
        let mut file = DummyFile::new();
        file.capacity = 0x100000;
        let mut handler = get_block_epoll_handler_with_file(file);
        let (control, receiver) = WorkerCaptureControl::new(handler.kill_evt.try_clone().unwrap());
        handler.capture_receiver = receiver;
        handler.capture = CaptureGate::new("test-drive/q0".to_string());
        let mem = handler.vm_as.clone();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        vq.dtable(0).set(0x1000, 16, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable(1)
            .set(0x2000, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 0);
        mem.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
            .unwrap();
        mem.write_obj::<u8>(0xff, GuestAddress(0x3000)).unwrap();
        vq.avail.ring(0).store(0);
        vq.avail.idx().store(1);
        handler.queue = VirtioQueueConfig::new(
            vq.create_queue(),
            Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            Arc::new(NoopNotifier::new()),
            0,
        );
        (handler, control)
    }

    fn capture_block_hold(
        handler: &mut InnerBlockEpollHandler<Arc<GuestMemoryMmap>, QueueSync>,
        control: &WorkerCaptureControl,
        generation: u64,
    ) -> mpsc::Receiver<crate::capture::CaptureResult<crate::capture::WorkerAck>> {
        let (reply, receiver) = mpsc::channel();
        control
            .sender
            .send(WorkerCommand::Hold {
                generation: CaptureGeneration(generation),
                deadline: Instant::now() + Duration::from_secs(1),
                reply,
            })
            .unwrap();
        control.wake.write(1).unwrap();
        let mut helper = EpollHelper::new().unwrap();
        assert!(!handler.handle_event(
            &mut helper,
            &epoll::Event::new(epoll::Events::EPOLLIN, KILL_EVENT as u64)
        ));
        receiver
    }

    #[test]
    fn capture_block_preserves_unconsumed_descriptors() {
        let (mut handler, control) = capture_block_fixture();
        let ack = capture_block_hold(&mut handler, &control, 1)
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(ack.device_id, "test-drive/q0");
        assert_eq!(ack.generation, 1);
        assert_eq!(ack.pending_io, 0);
        assert_eq!(ack.memory_writers, 0);
        assert!(ack.flush_completed);
        assert!(!handler.process_queue());
        assert!(handler.pending_req_map.is_empty());
        let mem = handler.vm_as.clone();
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x12a)).unwrap(), 0);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0xff);
    }

    #[test]
    fn capture_block_drains_taken_requests_before_ack() {
        let (mut handler, control) = capture_block_fixture();
        assert!(!handler.process_queue());
        assert_eq!(handler.pending_req_map.len(), 1);
        let ack = capture_block_hold(&mut handler, &control, 1);
        assert!(matches!(ack.try_recv(), Err(mpsc::TryRecvError::Empty)));
        let mut file = DummyFile::new();
        file.capacity = 0x100000;
        file.have_complete_io = true;
        handler.disk_image = Box::new(file);
        let mut helper = EpollHelper::new().unwrap();
        assert!(!handler.handle_event(
            &mut helper,
            &epoll::Event::new(epoll::Events::EPOLLIN, END_IO_EVENT as u64)
        ));
        let ack = ack.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(ack.pending_io, 0);
        assert!(ack.flush_completed);
        let mem = handler.vm_as.clone();
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x12a)).unwrap(), 1);
        assert_ne!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0xff);
    }

    #[test]
    fn capture_block_suppresses_queue_and_limiter_while_held() {
        let (mut handler, control) = capture_block_fixture();
        capture_block_hold(&mut handler, &control, 1)
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        handler.queue.eventfd.write(1).unwrap();
        let mut helper = EpollHelper::new().unwrap();
        for event in [QUEUE_AVAIL_EVENT, RATE_LIMITER_EVENT] {
            assert!(!handler.handle_event(
                &mut helper,
                &epoll::Event::new(epoll::Events::EPOLLIN, event as u64)
            ));
            assert!(handler.pending_req_map.is_empty());
            let mem = handler.vm_as.clone();
            assert_eq!(mem.read_obj::<u16>(GuestAddress(0x12a)).unwrap(), 0);
            assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0xff);
        }
    }

    #[test]
    fn capture_block_ready_limiter_does_not_consume_descriptors() {
        let (mut handler, control) = capture_block_fixture();
        handler.rate_limiter = RateLimiter::new(0, 0, 0, 1, 0, 1).unwrap();
        assert!(handler.rate_limiter.consume(1, TokenType::Ops));
        assert!(!handler.rate_limiter.consume(1, TokenType::Ops));
        capture_block_hold(&mut handler, &control, 1)
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let mut event = libc::pollfd {
            fd: handler.rate_limiter.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // The pollfd is live for the syscall; a deadline bounds the test without sleeping.
        assert_eq!(unsafe { libc::poll(&mut event, 1, 1000) }, 1);
        let mut helper = EpollHelper::new().unwrap();
        assert!(!handler.handle_event(
            &mut helper,
            &epoll::Event::new(epoll::Events::EPOLLIN, RATE_LIMITER_EVENT as u64)
        ));
        assert!(!handler.rate_limiter.is_blocked());
        assert!(handler.pending_req_map.is_empty());
        assert_eq!(
            handler.vm_as.read_obj::<u16>(GuestAddress(0x12a)).unwrap(),
            0
        );
    }

    #[test]
    fn capture_block_repeated_hold_and_wrong_generation() {
        let (mut handler, control) = capture_block_fixture();
        let first = capture_block_hold(&mut handler, &control, 1)
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(
            capture_block_hold(&mut handler, &control, 1)
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            first
        );
        for generation in [0, 2] {
            assert!(matches!(
                capture_block_hold(&mut handler, &control, generation)
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap(),
                Err(CaptureError::StaleGeneration)
            ));
        }
        assert!(!handler.process_queue());
        assert!(handler.pending_req_map.is_empty());
    }

    struct CaptureBlockWorker {
        kill: mpsc::Sender<KillEvent>,
        wake: EventFd,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Drop for CaptureBlockWorker {
        fn drop(&mut self) {
            let _ = self.kill.send(KillEvent::Kill);
            let _ = self.wake.write(1);
            if let Some(worker) = self.thread.take() {
                let result = worker.join();
                if !thread::panicking() {
                    result.unwrap();
                }
            }
        }
    }

    #[test]
    fn capture_block_real_aio_drains_and_resume_processes_saved_write() {
        let (mut handler, control) = capture_block_fixture();
        let file = TempFile::new().unwrap().into_file();
        file.set_len(4096).unwrap();
        let observer = file.try_clone().unwrap();
        let aio = Aio::new(file.as_raw_fd(), 16).unwrap();
        handler.disk_image = Box::new(LocalFile::new(file, false, aio).unwrap());
        let mem = handler.vm_as.clone();
        let queue_event = handler.queue.eventfd.clone();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        vq.dtable(0).set(0x1000, 16, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable(1).set(0x2000, 512, VIRTQ_DESC_F_NEXT, 2);
        vq.dtable(2).set(0x3000, 1, VIRTQ_DESC_F_WRITE, 0);
        vq.avail.ring(0).store(0);
        vq.avail.idx().store(1);
        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(0x1000))
            .unwrap();
        mem.write_slice(&[0x5a; 512], GuestAddress(0x2000)).unwrap();
        assert!(!handler.process_queue());
        assert_eq!(handler.pending_req_map.len(), 1);
        let (kill, receiver) = mpsc::channel();
        handler.evt_receiver = receiver;
        let wake = handler.kill_evt.try_clone().unwrap();
        let worker = CaptureBlockWorker {
            kill,
            wake,
            thread: Some(thread::spawn(move || handler.run().unwrap())),
        };
        let ack = control
            .request_hold(
                CaptureGeneration(1),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        assert_eq!(ack.pending_io, 0);
        assert!(ack.flush_completed);
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x12a)).unwrap(), 1);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0);
        let mut bytes = [0; 512];
        observer.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [0x5a; 512]);
        mem.write_slice(&[0xa5; 512], GuestAddress(0x2000)).unwrap();
        vq.avail.ring(1).store(0);
        vq.avail.idx().store(2);
        queue_event.write(1).unwrap();
        assert_eq!(
            control
                .request_hold(
                    CaptureGeneration(1),
                    Instant::now() + Duration::from_secs(3)
                )
                .unwrap(),
            ack
        );
        observer.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [0x5a; 512]);
        control
            .resume(
                CaptureGeneration(1),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        let second = control
            .request_hold(
                CaptureGeneration(2),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        assert_eq!(second.pending_io, 0);
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x12a)).unwrap(), 2);
        observer.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [0xa5; 512]);
        drop(worker);
        assert!(matches!(
            control.resume(
                CaptureGeneration(2),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(CaptureError::Disconnected)
        ));
    }

    #[test]
    fn capture_block_flush_failure_is_not_acknowledged() {
        let (mut handler, control) = capture_block_fixture();
        let mut file = DummyFile::new();
        file.flush_error = true;
        handler.disk_image = Box::new(file);
        assert!(matches!(
            capture_block_hold(&mut handler, &control, 1)
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            Err(CaptureError::FlushFailed(_))
        ));
        assert!(!handler.process_queue());
        assert!(handler.pending_req_map.is_empty());
    }

    #[test]
    fn capture_block_ack_timeout_is_not_success() {
        let (handler, control) = capture_block_fixture();
        assert!(matches!(
            control.request_hold(
                CaptureGeneration(1),
                Instant::now() + Duration::from_millis(5)
            ),
            Err(CaptureError::Timeout)
        ));
        drop(handler);
        assert!(matches!(
            control.request_hold(
                CaptureGeneration(1),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(CaptureError::Disconnected)
        ));
    }

    #[test]
    fn capture_block_activated_queues_report_logical_ids() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(4096).unwrap();
        let mut disks: Vec<Box<dyn Ufile>> = Vec::new();
        for _ in 0..2 {
            let file = file.try_clone().unwrap();
            let aio = Aio::new(file.as_raw_fd(), 16).unwrap();
            disks.push(Box::new(LocalFile::new(file, false, aio).unwrap()));
        }
        let manager = EpollManager::default();
        let mut device = Block::new(
            disks,
            false,
            false,
            Arc::new(vec![16, 16]),
            manager,
            vec![],
            false,
        )
        .unwrap();
        device.set_capture_id("block:root".to_string()).unwrap();
        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let queues = [0, 0x400]
            .iter()
            .enumerate()
            .map(|(index, base)| {
                let queue = VirtQueue::new(GuestAddress(*base), &mem, 16);
                VirtioQueueConfig::new(
                    queue.create_queue(),
                    Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                    Arc::new(NoopNotifier::new()),
                    index as u16,
                )
            })
            .collect();
        let config = VirtioDeviceConfig::<Arc<GuestMemoryMmap>>::new(
            mem,
            create_address_space(),
            Arc::new(Kvm::new().unwrap().create_vm().unwrap()),
            DeviceResources::new(),
            queues,
            None,
            Arc::new(NoopNotifier::new()),
        );
        device.activate(config).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let report = device.request_hold(CaptureGeneration(1), deadline);
        let resume = device.resume_capture(CaptureGeneration(1), deadline);
        // Always join the actual activation workers before asserting reports.
        VirtioDevice::<Arc<GuestMemoryMmap>, QueueSync, GuestRegionMmap>::remove(&mut device);
        let report = report.unwrap();
        assert_eq!(
            report
                .iter()
                .map(|ack| ack.device_id.as_str())
                .collect::<Vec<_>>(),
            ["block:root/q0", "block:root/q1"]
        );
        assert!(report.iter().all(|ack| ack.generation == 1
            && ack.flush_completed
            && ack.pending_io == 0
            && ack.memory_writers == 0));
        resume.unwrap();
    }

    #[test]
    fn capture_block_unactivated_device_cannot_ack_empty_worker_set() {
        let mut file = DummyFile::new();
        file.capacity = 0x100000;
        let block = Block::<Arc<GuestMemoryMmap>>::new(
            vec![Box::new(file)],
            false,
            false,
            Arc::new(vec![]),
            EpollManager::default(),
            vec![],
            false,
        )
        .unwrap();
        assert!(matches!(
            block.request_hold(
                CaptureGeneration(1),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(CaptureError::Disconnected)
        ));
        assert!(matches!(
            block.resume_capture(
                CaptureGeneration(1),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(CaptureError::Disconnected)
        ));
    }

    #[test]
    fn capture_block_resume_kicks_saved_queue() {
        let (mut handler, control) = capture_block_fixture();
        capture_block_hold(&mut handler, &control, 1)
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let (reply, receiver) = mpsc::channel();
        control
            .sender
            .send(WorkerCommand::Resume {
                generation: CaptureGeneration(1),
                deadline: Instant::now() + Duration::from_secs(1),
                reply,
            })
            .unwrap();
        control.wake.write(1).unwrap();
        let mut helper = EpollHelper::new().unwrap();
        assert!(!handler.handle_event(
            &mut helper,
            &epoll::Event::new(epoll::Events::EPOLLIN, KILL_EVENT as u64)
        ));
        receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(handler.pending_req_map.len(), 1);
        assert!(matches!(
            capture_block_hold(&mut handler, &control, 1)
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            Err(CaptureError::StaleGeneration)
        ));
    }

    #[test]
    fn test_block_epoll_handler_io_complete() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        // no data
        let mut handler = get_block_epoll_handler();
        let mut data_descs = Vec::with_capacity(CONFIG_MAX_SEG as usize);
        assert!(handler.io_complete().is_ok());

        // have data
        let mut file = DummyFile::new();
        file.have_complete_io = true;
        let disk_image = Box::new(file);
        handler.disk_image = disk_image;

        // no data in pending_req_map
        assert!(matches!(handler.io_complete(), Err(Error::InternalError)));

        // data in pending_req_map
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        assert!(vq.end().0 < 0x1000);
        vq.avail.ring(0).store(0);
        vq.avail.idx().store(1);
        let mut q = vq.create_queue();
        vq.dtable(0).set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
        vq.dtable(1)
            .set(0x2000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
        vq.dtable(2).set(0x0, 1, VIRTQ_DESC_F_WRITE, 1);
        m.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
            .unwrap();
        let req = Request::parse(
            &mut q.pop_descriptor_chain(m).unwrap(),
            &mut data_descs,
            0x100000,
        )
        .unwrap();
        handler.pending_req_map.insert(0, req);
        handler.io_complete().unwrap();
    }
}
