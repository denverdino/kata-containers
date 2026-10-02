// Copyright (C) 2020 Alibaba Cloud Computing. All rights reserved.
// Copyright (c) 2020 Ant Financial
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![allow(dead_code)]

use std::any::Any;
use std::cmp;
use std::convert::TryFrom;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::time::Instant;

use dbs_device::resources::ResourceConstraint;
use dbs_interrupt::{InterruptNotifier, NoopNotifier};
use dbs_utils::epoll_manager::{
    EpollManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberId,
};
use dbs_utils::metric::{IncMetric, SharedIncMetric, SharedStoreMetric, StoreMetric};
use log::{debug, error, info, trace};
use serde::{Deserialize, Serialize};
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1};
use virtio_queue::{QueueOwnedT, QueueSync, QueueT};
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryRegion,
    GuestRegionMmap, MemoryRegionAddress,
};

use crate::capture::{CaptureError, CaptureGate, CaptureGeneration, CaptureResult, WorkerAck};
use crate::device::{VirtioDevice, VirtioDeviceConfig, VirtioDeviceInfo, VirtioQueueConfig};
use crate::{
    ActivateResult, ConfigError, ConfigResult, DbsGuestAddressSpace, Error, Result, TYPE_BALLOON,
};

const BALLOON_DRIVER_NAME: &str = "virtio-balloon";

// Supported fields in the configuration space:
const CONFIG_SPACE_SIZE: usize = 16;

const QUEUE_SIZE: u16 = 128;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
const PMD_SHIFT: u64 = 21;
const PMD_SIZE: u64 = 1 << PMD_SHIFT;

// New descriptors are pending on the virtio queue.
const INFLATE_QUEUE_AVAIL_EVENT: u32 = 0;
// New descriptors are pending on the virtio queue.
const DEFLATE_QUEUE_AVAIL_EVENT: u32 = 1;
// New descriptors are pending on the virtio queue.
const REPORTING_QUEUE_AVAIL_EVENT: u32 = 2;
// The device has been dropped.
const KILL_EVENT: u32 = 3;
// The device should be paused.
const PAUSE_EVENT: u32 = 4;
const BALLOON_EVENTS_COUNT: u32 = 5;

// Page shift in the host.
const PAGE_SHIFT: u32 = 12;
// Huge Page shift in the host.
const HUGE_PAGE_SHIFT: u32 = 21;

// Size of a PFN in the balloon interface.
const VIRTIO_BALLOON_PFN_SHIFT: u64 = 12;
// feature to deflate balloon on OOM
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: usize = 2;
// feature to enable free page reporting
const VIRTIO_BALLOON_F_REPORTING: usize = 5;

// The PAGE_REPORTING_CAPACITY of CLH is set to 32.
// This value is got from patch in https://patchwork.kernel.org/patch/11377073/.
// But dragonball reporting capacity is set to 128 in before.
// So I keep 128.
const PAGE_REPORTING_CAPACITY: u16 = 128;

#[derive(Debug, thiserror::Error)]
pub enum BalloonError {}

/// Balloon Device associated metrics.
#[derive(Default, Serialize)]
pub struct BalloonDeviceMetrics {
    /// Number of times when handling events on a balloon device.
    pub event_count: SharedIncMetric,
    /// Number of times when activate failed on a balloon device.
    pub activate_fails: SharedIncMetric,
    /// Number of balloon device inflations.
    pub inflate_count: SharedIncMetric,
    /// Number of balloon device deflations.
    pub deflate_count: SharedIncMetric,
    /// Memory size(mb) of balloon device.
    pub balloon_size_mb: SharedStoreMetric,
    /// Number of balloon device reportions
    pub reporting_count: SharedIncMetric,
    /// Number of times when handling events on a balloon device failed.
    pub event_fails: SharedIncMetric,
}

pub type BalloonResult<T> = std::result::Result<T, BalloonError>;

/// Memory-owner operation for guest-returned full pages. Never modifies a lower image.
pub trait BalloonReclaimer: Send + Sync {
    fn reclaim_private_range(&self, guest_addr: u64, length: u64) -> io::Result<()>;
}

// Capture and epoll callbacks own the same concrete handler lock. No callback can
// still be writing guest memory when a successful hold acknowledgement is returned.
struct BalloonSubscriber<T>(Arc<Mutex<T>>);

impl<T: MutEventSubscriber> MutEventSubscriber for BalloonSubscriber<T> {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        self.0
            .lock()
            .expect("balloon handler lock poisoned")
            .process(events, ops);
    }

    fn init(&mut self, ops: &mut EventOps) {
        self.0
            .lock()
            .expect("balloon handler lock poisoned")
            .init(ops);
    }
}

trait BalloonCaptureController: Send {
    fn request_hold(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<WorkerAck>;
    fn resume_capture(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<()>;
}

/// Cloneable control for an activated balloon handler, independent of its transport lock.
#[derive(Clone)]
pub struct BalloonCaptureControl(Arc<Mutex<dyn BalloonCaptureController>>);

impl BalloonCaptureControl {
    fn with_handler<T>(
        &self,
        deadline: Instant,
        action: impl FnOnce(&mut dyn BalloonCaptureController) -> CaptureResult<T>,
    ) -> CaptureResult<T> {
        loop {
            if Instant::now() >= deadline {
                return Err(CaptureError::Timeout);
            }
            match self.0.try_lock() {
                Ok(mut handler) => return action(&mut *handler),
                Err(TryLockError::Poisoned(_)) => return Err(CaptureError::Disconnected),
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            }
        }
    }

    /// Wait for any in-progress callback and freeze subsequent inflate/deflate/reporting writes.
    pub fn request_hold(
        &self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<WorkerAck> {
        self.with_handler(deadline, |handler| {
            handler.request_hold(generation, deadline)
        })
    }

    /// Release the exact generation and kick the saved queues.
    pub fn resume_capture(
        &self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<()> {
        self.with_handler(deadline, |handler| {
            handler.resume_capture(generation, deadline)
        })
    }
}

// Got from include/uapi/linux/virtio_balloon.h
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct VirtioBalloonConfig {
    // Number of pages host wants Guest to give up.
    pub(crate) num_pages: u32,
    // Number of pages we've actually got in balloon.
    pub(crate) actual: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

pub struct BalloonEpollHandler<
    AS: GuestAddressSpace,
    Q: QueueT + Send = QueueSync,
    R: GuestMemoryRegion = GuestRegionMmap,
> {
    pub(crate) config: VirtioDeviceConfig<AS, Q, R>,
    pub(crate) inflate: VirtioQueueConfig<Q>,
    pub(crate) deflate: VirtioQueueConfig<Q>,
    pub(crate) reporting: Option<VirtioQueueConfig<Q>>,
    balloon_config: Arc<Mutex<VirtioBalloonConfig>>,
    metrics: Arc<BalloonDeviceMetrics>,
    capture: CaptureGate,
    reclaimer: Option<Arc<dyn BalloonReclaimer>>,
}

impl<AS: DbsGuestAddressSpace, Q: QueueT + Send, R: GuestMemoryRegion + Send + Sync>
    BalloonCaptureController for BalloonEpollHandler<AS, Q, R>
{
    fn request_hold(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<WorkerAck> {
        let (reply, receiver) = mpsc::channel();
        self.capture.begin(generation, deadline, reply);
        if self.capture.needs_ack() {
            self.capture.finish_report(Ok(self.capture.held_ack(false)));
        }
        receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| CaptureError::Timeout)?
    }

    fn resume_capture(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<()> {
        if deadline <= Instant::now() {
            return Err(CaptureError::Timeout);
        }
        if self.capture.release(generation)? {
            for queue in [
                Some(&self.inflate),
                Some(&self.deflate),
                self.reporting.as_ref(),
            ]
            .iter()
            .flatten()
            {
                queue
                    .generate_event()
                    .map_err(|error| CaptureError::ControlIo(error.to_string()))?;
            }
        }
        Ok(())
    }
}

impl<AS: DbsGuestAddressSpace, Q: QueueT + Send, R: GuestMemoryRegion>
    BalloonEpollHandler<AS, Q, R>
{
    fn process_reporting_queue(&mut self) -> bool {
        if self.capture.is_held() {
            return true;
        }
        self.metrics.reporting_count.inc();
        if let Some(queue) = &mut self.reporting {
            if let Err(e) = queue.consume_event() {
                error!("Failed to get reporting queue event: {e:?}");
                return false;
            }
            let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
            let mut used_count = 0;
            let conf = &mut self.config;
            let guard = conf.lock_guest_memory();
            let mem = guard.deref().memory();

            let mut queue_guard = queue.queue_mut().lock();

            let mut iter = match queue_guard.iter(mem) {
                Err(e) => {
                    error!("virtio-balloon: failed to process reporting queue. {e}");
                    return false;
                }
                Ok(iter) => iter,
            };

            for mut desc_chain in &mut iter {
                let mut next_desc = desc_chain.next();
                let mut len = 0;
                while let Some(avail_desc) = next_desc {
                    if !(avail_desc.len() as usize).is_multiple_of(size_of::<u32>()) {
                        error!("the request size {} is not right", avail_desc.len());
                        break;
                    }
                    let size = avail_desc.len();
                    let addr = avail_desc.addr();
                    len += size;

                    if let Some(owner) = &self.reclaimer {
                        if let Err(error) = owner.reclaim_private_range(addr.0, u64::from(size)) {
                            error!("balloon reporting reclaim failed: {error}");
                        }
                    } else if let Some(region) = mem.find_region(addr) {
                        let host_addr = match mem.get_host_address(addr) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("virtio-balloon get host address failed! addr:{:x} size: {:x} error:{:?}", addr.0, size, e);
                                break;
                            }
                        };
                        if region.file_offset().is_some() {
                            // when guest memory has file backend we use fallocate free memory
                            let file_offset = region.file_offset().unwrap();
                            let file_fd = file_offset.file().as_raw_fd();
                            let file_start = file_offset.start();
                            let mode = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
                            let start_addr =
                                region.get_host_address(MemoryRegionAddress(0)).unwrap();
                            let offset = file_start as i64 + host_addr as i64 - start_addr as i64;
                            if let Err(e) = Self::do_fallocate(file_fd, offset, size as i64, mode) {
                                info!(
                                    "virtio-balloon reporting failed fallocate guest address: {:x}  offset: {:x} size {:x} fd {:?}",
                                    addr.0,
                                    offset,
                                    size,
                                    file_fd
                                );
                                error!("fallocate get error {e}");
                            }
                        } else {
                            // when guest memory have no file backend or comes from we use madvise free memory
                            let advise = libc::MADV_DONTNEED;
                            if let Err(e) = Self::do_madvise(
                                host_addr as *mut libc::c_void,
                                size as usize,
                                advise,
                            ) {
                                info!(
                                    "guest address: {:?}  host address: {:?} size {:?} advise {:?}",
                                    addr,
                                    host_addr,
                                    1 << PAGE_SHIFT,
                                    advise
                                );
                                error!("madvise get error {e}");
                            }
                        }
                    }
                    next_desc = desc_chain.next();
                }
                used_desc_heads[used_count] = (desc_chain.head_index(), len);
                used_count += 1;
            }

            drop(queue_guard);

            for &(desc_index, len) in &used_desc_heads[..used_count] {
                queue.add_used(mem, desc_index, len);
            }
            if used_count > 0 {
                match queue.notify() {
                    Ok(_v) => true,
                    Err(e) => {
                        error!("{BALLOON_DRIVER_NAME}: Failed to signal device change event: {e}");
                        false
                    }
                }
            } else {
                true
            }
        } else {
            error!("{BALLOON_DRIVER_NAME}: Invalid event: Free pages reporting was not configured");
            false
        }
    }

    fn process_queue(&mut self, idx: u32) -> bool {
        if self.capture.is_held() {
            return true;
        }
        let conf = &mut self.config;
        match idx {
            INFLATE_QUEUE_AVAIL_EVENT => self.metrics.inflate_count.inc(),
            DEFLATE_QUEUE_AVAIL_EVENT => self.metrics.deflate_count.inc(),
            _ => {}
        }
        let queue = match idx {
            INFLATE_QUEUE_AVAIL_EVENT => &mut self.inflate,
            DEFLATE_QUEUE_AVAIL_EVENT => &mut self.deflate,
            _ => {
                error!("{BALLOON_DRIVER_NAME}: unsupport idx {idx}");
                return false;
            }
        };

        if let Err(e) = queue.consume_event() {
            error!("{BALLOON_DRIVER_NAME}: Failed to get idx {idx} queue event: {e:?}");
            return false;
        }

        let mut advice = match idx {
            INFLATE_QUEUE_AVAIL_EVENT => libc::MADV_DONTNEED,
            DEFLATE_QUEUE_AVAIL_EVENT => libc::MADV_WILLNEED,
            _ => {
                error!("{BALLOON_DRIVER_NAME}: balloon idx: {idx:?} is not right");
                return false;
            }
        };

        let mut used_desc_heads = [0; QUEUE_SIZE as usize];
        let mut used_count = 0;
        let guard = conf.lock_guest_memory();
        let mem = guard.deref().memory();

        let mut queue_guard = queue.queue_mut().lock();

        let mut iter = match queue_guard.iter(mem) {
            Err(e) => {
                error!("virtio-balloon: failed to process queue. {e}");
                return false;
            }
            Ok(iter) => iter,
        };

        for mut desc_chain in &mut iter {
            let avail_desc = match desc_chain.next() {
                Some(avail_desc) => avail_desc,
                None => {
                    error!(
                        "{BALLOON_DRIVER_NAME}: Failed to parse balloon available descriptor chain"
                    );
                    return false;
                }
            };

            if avail_desc.is_write_only() {
                error!("{BALLOON_DRIVER_NAME}: The head contains the request type is not right");
                continue;
            }
            let avail_desc_len = avail_desc.len();
            if !(avail_desc_len as usize).is_multiple_of(size_of::<u32>()) {
                error!("{BALLOON_DRIVER_NAME}: the request size {avail_desc_len} is not right");
                continue;
            }

            let mut offset = 0u64;
            while offset < avail_desc_len as u64 {
                // Get pfn
                let pfn: u32 = match mem.read_obj(GuestAddress(avail_desc.addr().0 + offset)) {
                    Ok(ret) => ret,
                    Err(e) => {
                        error!(
                            "{}: Fail to read addr {}: {:?}",
                            BALLOON_DRIVER_NAME,
                            avail_desc.addr().0 + offset,
                            e
                        );
                        break;
                    }
                };
                offset += size_of::<u32>() as u64;

                // Get pfn_len
                let pfn_len = match idx {
                    INFLATE_QUEUE_AVAIL_EVENT | DEFLATE_QUEUE_AVAIL_EVENT => 1 << PAGE_SHIFT,
                    _ => {
                        error!("{BALLOON_DRIVER_NAME}: balloon idx: {idx:?} is not right");
                        return false;
                    }
                };

                trace!("{BALLOON_DRIVER_NAME}: process_queue pfn {pfn} len {pfn_len}");

                let guest_addr = (pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT;

                if let Some(owner) = &self.reclaimer {
                    if idx == INFLATE_QUEUE_AVAIL_EVENT {
                        if let Err(error) = owner.reclaim_private_range(guest_addr, pfn_len as u64)
                        {
                            error!("balloon inflate reclaim failed: {error}");
                        }
                    }
                    // Deflate only returns ownership to the guest; it must never
                    // refault the original nonzero ancestor or undo private zeros.
                } else if let Some(region) = mem.find_region(GuestAddress(guest_addr)) {
                    let host_addr = mem.get_host_address(GuestAddress(guest_addr)).unwrap();
                    if advice == libc::MADV_DONTNEED && region.file_offset().is_some() {
                        advice = libc::MADV_REMOVE;
                    }
                    if let Err(e) = Self::do_madvise(
                        host_addr as *mut libc::c_void,
                        pfn_len as libc::size_t,
                        advice,
                    ) {
                        info!(
                            "{BALLOON_DRIVER_NAME}: guest address: {guest_addr:?}  host address: {host_addr:?} size {pfn_len:?} advise {advice:?}"
                        );
                        error!("{BALLOON_DRIVER_NAME}: madvise get error {e}");
                    }
                } else {
                    error!(
                        "{BALLOON_DRIVER_NAME}: guest address 0x{guest_addr:x} size {pfn_len:?} advise {advice:?} is not available"
                    );
                }
            }

            used_desc_heads[used_count] = desc_chain.head_index();
            used_count += 1;
        }

        drop(queue_guard);

        for &desc_index in &used_desc_heads[..used_count] {
            queue.add_used(mem, desc_index, 0);
        }
        if used_count > 0 {
            match queue.notify() {
                Ok(_v) => true,
                Err(e) => {
                    error!("{BALLOON_DRIVER_NAME}: Failed to signal device queue event: {e}");
                    false
                }
            }
        } else {
            true
        }
    }

    fn do_madvise(
        addr: *mut libc::c_void,
        size: libc::size_t,
        advise: libc::c_int,
    ) -> std::result::Result<(), io::Error> {
        let res = unsafe { libc::madvise(addr, size, advise) };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn do_fallocate(
        file_fd: RawFd,
        offset: libc::off_t,
        len: libc::off_t,
        mode: libc::c_int,
    ) -> std::result::Result<(), io::Error> {
        let res = unsafe { libc::fallocate(file_fd, mode, offset, len) };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl<AS: DbsGuestAddressSpace, Q: QueueT + Send, R: GuestMemoryRegion> MutEventSubscriber
    for BalloonEpollHandler<AS, Q, R>
where
    AS: 'static + GuestAddressSpace + Send + Sync,
{
    fn init(&mut self, ops: &mut EventOps) {
        trace!(
            target: BALLOON_DRIVER_NAME,
            "{BALLOON_DRIVER_NAME}: BalloonEpollHandler::init()",
        );
        let events = Events::with_data(
            self.inflate.eventfd.as_ref(),
            INFLATE_QUEUE_AVAIL_EVENT,
            EventSet::IN,
        );
        if let Err(e) = ops.add(events) {
            error!("{BALLOON_DRIVER_NAME}: failed to register INFLATE QUEUE event, {e:?}");
        }

        let events = Events::with_data(
            self.deflate.eventfd.as_ref(),
            DEFLATE_QUEUE_AVAIL_EVENT,
            EventSet::IN,
        );
        if let Err(e) = ops.add(events) {
            error!("{BALLOON_DRIVER_NAME}: failed to register deflate queue event, {e:?}");
        }

        if let Some(reporting) = &self.reporting {
            let events = Events::with_data(
                reporting.eventfd.as_ref(),
                REPORTING_QUEUE_AVAIL_EVENT,
                EventSet::IN,
            );
            if let Err(e) = ops.add(events) {
                error!("{BALLOON_DRIVER_NAME}: failed to register reporting queue event, {e:?}");
            }
        }
    }

    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        if self.capture.is_held() {
            // Drain eventfds, never descriptors. Resume kicks all saved queues.
            let queue = match events.data() {
                INFLATE_QUEUE_AVAIL_EVENT => Some(&self.inflate),
                DEFLATE_QUEUE_AVAIL_EVENT => Some(&self.deflate),
                REPORTING_QUEUE_AVAIL_EVENT => self.reporting.as_ref(),
                _ => None,
            };
            if let Some(queue) = queue {
                let _ = queue.consume_event();
            }
            return;
        }
        let guard = self.config.lock_guest_memory();
        let _mem = guard.deref();
        let idx = events.data();

        trace!(
            target: BALLOON_DRIVER_NAME,
            "{BALLOON_DRIVER_NAME}: BalloonEpollHandler::process() idx {idx}"
        );
        self.metrics.event_count.inc();
        match idx {
            INFLATE_QUEUE_AVAIL_EVENT | DEFLATE_QUEUE_AVAIL_EVENT => {
                if !self.process_queue(idx) {
                    self.metrics.event_fails.inc();
                    error!("{BALLOON_DRIVER_NAME}: Failed to handle {idx} queue");
                }
            }
            REPORTING_QUEUE_AVAIL_EVENT => {
                if !self.process_reporting_queue() {
                    self.metrics.event_fails.inc();
                    error!("Failed to handle reporting queue");
                }
            }
            KILL_EVENT => {
                debug!("kill_evt received");
            }
            _ => {
                error!("{BALLOON_DRIVER_NAME}: unknown idx {idx}");
            }
        }
    }
}

fn page_number_to_mib(number: u64) -> u64 {
    number << PAGE_SHIFT >> 10 >> 10
}

fn mib_to_page_number(mib: u64) -> u64 {
    mib << 10 << 10 >> PAGE_SHIFT
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Balloon<AS: GuestAddressSpace> {
    pub(crate) device_info: VirtioDeviceInfo,
    pub(crate) config: Arc<Mutex<VirtioBalloonConfig>>,
    pub(crate) paused: Arc<AtomicBool>,
    pub(crate) device_change_notifier: Arc<dyn InterruptNotifier>,
    pub(crate) subscriber_id: Option<SubscriberId>,
    pub(crate) phantom: PhantomData<AS>,
    metrics: Arc<BalloonDeviceMetrics>,
    capture_controller: Option<BalloonCaptureControl>,
    capture_id: String,
    capture_on_activate: Option<CaptureGeneration>,
    reclaimer: Option<Arc<dyn BalloonReclaimer>>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct BalloonConfig {
    pub f_deflate_on_oom: bool,
    pub f_reporting: bool,
}

impl<AS: GuestAddressSpace> Balloon<AS> {
    // Create a new virtio-balloon.
    pub fn new(
        epoll_mgr: EpollManager,
        cfg: BalloonConfig,
        f_access_platform: bool,
    ) -> Result<Self> {
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if f_access_platform {
            avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        }

        let mut queue_sizes = QUEUE_SIZES.to_vec();

        if cfg.f_deflate_on_oom {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        }
        if cfg.f_reporting {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_REPORTING;
            queue_sizes.push(PAGE_REPORTING_CAPACITY);
        }

        let config = VirtioBalloonConfig::default();

        Ok(Balloon {
            device_info: VirtioDeviceInfo::new(
                BALLOON_DRIVER_NAME.to_string(),
                avail_features,
                Arc::new(queue_sizes),
                config.as_slice().to_vec(),
                epoll_mgr,
            ),
            config: Arc::new(Mutex::new(config)),
            paused: Arc::new(AtomicBool::new(false)),
            device_change_notifier: Arc::new(NoopNotifier::new()),
            subscriber_id: None,
            phantom: PhantomData,
            metrics: Arc::new(BalloonDeviceMetrics::default()),
            capture_controller: None,
            capture_id: BALLOON_DRIVER_NAME.into(),
            capture_on_activate: None,
            reclaimer: None,
        })
    }

    /// Bind capture identity and the RAM owner before activation.
    pub fn set_capture_memory(
        &mut self,
        id: String,
        reclaimer: Arc<dyn BalloonReclaimer>,
    ) -> Result<()> {
        if id.is_empty() || self.subscriber_id.is_some() {
            return Err(Error::InvalidInput);
        }
        self.capture_id = id;
        self.reclaimer = Some(reclaimer);
        Ok(())
    }

    /// Arm a restored device before activation can register a writer.
    pub fn arm_capture(&mut self, generation: CaptureGeneration) -> CaptureResult<()> {
        if generation.0 == 0
            || self.capture_controller.is_some()
            || self.capture_on_activate.is_some()
            || self.reclaimer.is_none()
        {
            return Err(CaptureError::StaleGeneration);
        }
        self.capture_on_activate = Some(generation);
        Ok(())
    }

    /// Access the callback lock without retaining the MMIO transport lock.
    pub fn capture_control(&self) -> CaptureResult<BalloonCaptureControl> {
        if self.reclaimer.is_none() {
            return Err(CaptureError::Disconnected);
        }
        self.capture_controller
            .clone()
            .ok_or(CaptureError::Disconnected)
    }

    pub fn set_size(&self, size_mb: u64) -> Result<()> {
        self.metrics.balloon_size_mb.store(size_mb as usize);
        let num_pages = mib_to_page_number(size_mb);

        let balloon_config = &mut self.config.lock().unwrap();
        balloon_config.num_pages = num_pages as u32;
        if let Err(e) = self.device_change_notifier.notify() {
            error!("{BALLOON_DRIVER_NAME}: failed to signal device change event: {e}");
            return Err(Error::IOError(e));
        }

        Ok(())
    }

    pub fn metrics(&self) -> Arc<BalloonDeviceMetrics> {
        self.metrics.clone()
    }
}

/// Balloon-specific snapshot state. Queue progress and activation are persisted
/// by the enclosing MMIO transport, using the handler's shared queue objects.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BalloonState {
    pub device_info: crate::persist::VirtioDeviceInfoState,
    pub num_pages: u32,
    pub actual: u32,
}

impl<'a, AS: GuestAddressSpace> crate::persist::VirtioDevicePersist<'a> for Balloon<AS> {
    type State = BalloonState;
    type SaveArgs = ();
    type RestoreArgs = ();
    type Error = Error;

    fn save_state(&mut self, _: ()) -> Result<Self::State> {
        let config = self.config.lock().map_err(|_| Error::InvalidInput)?;
        let mut device_info = self.device_info.save_state();
        device_info.config_space = config.as_slice().to_vec();
        Ok(BalloonState {
            device_info,
            num_pages: config.num_pages,
            actual: config.actual,
        })
    }

    fn restore_state(&mut self, state: &Self::State, _: ()) -> Result<()> {
        let config = VirtioBalloonConfig {
            num_pages: state.num_pages,
            actual: state.actual,
        };
        if self.subscriber_id.is_some()
            || state.device_info.acked_features & !state.device_info.avail_features != 0
            || state.device_info.config_space != config.as_slice()
        {
            return Err(Error::InvalidInput);
        }
        self.device_info.restore_state(&state.device_info)?;
        *self.config.lock().map_err(|_| Error::InvalidInput)? = config;
        Ok(())
    }
}

impl<AS, Q, R> VirtioDevice<AS, Q, R> for Balloon<AS>
where
    AS: DbsGuestAddressSpace,
    Q: QueueT + Send + 'static,
    R: GuestMemoryRegion + Sync + Send + 'static,
{
    fn device_type(&self) -> u32 {
        TYPE_BALLOON
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.device_info.queue_sizes
    }

    fn get_avail_features(&self, page: u32) -> u32 {
        self.device_info.get_avail_features(page)
    }

    fn set_acked_features(&mut self, page: u32, value: u32) {
        trace!(
            target: BALLOON_DRIVER_NAME,
            "{BALLOON_DRIVER_NAME}: VirtioDevice::set_acked_features({page}, 0x{value:x})"
        );
        self.device_info.set_acked_features(page, value)
    }

    fn read_config(&mut self, offset: u64, mut data: &mut [u8]) -> ConfigResult {
        trace!(
            target: BALLOON_DRIVER_NAME,
            "{BALLOON_DRIVER_NAME}: VirtioDevice::read_config(0x{offset:x}, {data:?})"
        );
        let config = &self.config.lock().unwrap();
        let config_space = config.as_slice().to_vec();
        let config_len = config_space.len() as u64;
        if offset >= config_len {
            error!(
                "{BALLOON_DRIVER_NAME}: config space read request out of range, offset {offset}"
            );
            return Err(ConfigError::InvalidOffset(offset));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
        Ok(())
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> ConfigResult {
        let config = &mut self.config.lock().unwrap();
        let config_slice = config.as_mut_slice();
        let Ok(start) = usize::try_from(offset) else {
            error!("Failed to write config space");
            return Err(ConfigError::InvalidOffset(offset));
        };
        let Some(dst) = start
            .checked_add(data.len())
            .and_then(|end| config_slice.get_mut(start..end))
        else {
            error!("Failed to write config space");
            return Err(ConfigError::InvalidOffsetPlusDataLen(
                offset + data.len() as u64,
            ));
        };
        dst.copy_from_slice(data);
        Ok(())
    }

    fn activate(&mut self, mut config: VirtioDeviceConfig<AS, Q, R>) -> ActivateResult {
        self.device_info
            .check_queue_sizes(&config.queues)
            .inspect_err(|_| self.metrics.activate_fails.inc())?;
        self.device_change_notifier = config.device_change_notifier.clone();

        trace!(
            "{}: activate acked_features 0x{:x}",
            BALLOON_DRIVER_NAME,
            self.device_info.acked_features
        );

        let inflate = config.queues.remove(0);
        let deflate = config.queues.remove(0);
        let mut reporting = None;
        if (self.device_info.acked_features & (1u64 << VIRTIO_BALLOON_F_REPORTING)) != 0 {
            reporting = Some(config.queues.remove(0));
        }

        let mut capture = CaptureGate::armed(self.capture_id.clone(), self.capture_on_activate);
        if capture.is_held() {
            capture.finish_report(Ok(capture.held_ack(false)));
        }
        let handler = Arc::new(Mutex::new(BalloonEpollHandler {
            config,
            inflate,
            deflate,
            reporting,
            balloon_config: self.config.clone(),
            metrics: self.metrics.clone(),
            capture,
            reclaimer: self.reclaimer.clone(),
        }));

        self.capture_controller = Some(BalloonCaptureControl(handler.clone()));
        self.subscriber_id = Some(
            self.device_info
                .register_event_handler(Box::new(BalloonSubscriber(handler))),
        );

        Ok(())
    }

    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    ) {
        requests.push(ResourceConstraint::LegacyIrq { irq: None });
        if use_generic_irq {
            requests.push(ResourceConstraint::GenericIrq {
                size: (self.device_info.queue_sizes.len() + 1) as u32,
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
pub(crate) mod tests {
    use dbs_device::resources::DeviceResources;
    use dbs_utils::epoll_manager::SubscriberOps;
    use kvm_ioctls::Kvm;
    use test_utils::skip_if_kvm_unaccessable;
    use vm_memory::GuestMemoryMmap;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::tests::{create_address_space, VirtQueue};

    fn create_balloon_epoll_handler() -> BalloonEpollHandler<Arc<GuestMemoryMmap>> {
        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), 0x10000)]).unwrap());
        let queues = vec![VirtioQueueConfig::create(128, 0).unwrap()];
        let resources = DeviceResources::new();
        let kvm = Kvm::new().unwrap();
        let vm_fd = Arc::new(kvm.create_vm().unwrap());
        let address_space = create_address_space();

        let config = VirtioDeviceConfig::new(
            mem,
            address_space,
            vm_fd,
            resources,
            queues,
            None,
            Arc::new(NoopNotifier::new()),
        );

        let inflate = VirtioQueueConfig::create(128, 0).unwrap();
        let deflate = VirtioQueueConfig::create(128, 0).unwrap();
        let reporting = Some(VirtioQueueConfig::create(128, 0).unwrap());
        let balloon_config = Arc::new(Mutex::new(VirtioBalloonConfig::default()));
        let metrics = Arc::new(BalloonDeviceMetrics::default());
        BalloonEpollHandler {
            config,
            inflate,
            deflate,
            reporting,
            balloon_config,
            metrics,
            capture: CaptureGate::new(BALLOON_DRIVER_NAME.to_string()),
            reclaimer: None,
        }
    }

    #[test]
    fn m2_balloon_held_blocks_reporting() {
        let mut handler = create_balloon_epoll_handler();
        let memory = handler.config.vm_as.clone();
        let vq = VirtQueue::new(GuestAddress(0), &memory, 16);
        let queue = vq.create_queue();
        vq.avail.idx().store(1);
        vq.avail.ring(0).store(0);
        vq.dtable(0).set(0x2000, 0x1000, 2, 0);
        memory
            .write_slice(&[0x71; 4096], GuestAddress(0x2000))
            .unwrap();
        handler.reporting = Some(VirtioQueueConfig::new(
            queue,
            Arc::new(EventFd::new(0).unwrap()),
            Arc::new(NoopNotifier::new()),
            2,
        ));
        handler
            .reporting
            .as_ref()
            .unwrap()
            .generate_event()
            .unwrap();
        handler.capture = CaptureGate::armed("balloon:test".into(), Some(CaptureGeneration(1)));
        assert!(handler.process_reporting_queue());
        assert_eq!(
            handler.reporting.as_ref().unwrap().queue().next_used(),
            0,
            "held reporting must not consume descriptors or update the used ring"
        );
        assert_eq!(memory.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0x71);
    }

    #[test]
    fn m2_balloon_restore_preserves_progress() {
        use crate::persist::VirtioDevicePersist;
        let create = || {
            Balloon::<Arc<GuestMemoryMmap>>::new(
                EpollManager::default(),
                BalloonConfig {
                    f_deflate_on_oom: true,
                    f_reporting: true,
                },
                false,
            )
            .unwrap()
        };
        let mut source = create();
        source.set_size(17).unwrap();
        source.config.lock().unwrap().actual = 321;
        source.device_info.acked_features = source.device_info.avail_features;
        let state = source.save_state(()).unwrap();
        let encoded = serde_json::to_vec(&state).unwrap();
        let mut restored = create();
        restored
            .restore_state(&serde_json::from_slice(&encoded).unwrap(), ())
            .unwrap();
        assert_eq!(
            *restored.config.lock().unwrap(),
            *source.config.lock().unwrap()
        );
        assert_eq!(
            restored.device_info.acked_features,
            source.device_info.acked_features
        );
    }

    #[test]
    fn m2_balloon_callback_lock_and_resume() {
        use std::time::Duration;
        let mut handler = create_balloon_epoll_handler();
        let memory = handler.config.vm_as.clone();
        let vq = VirtQueue::new(GuestAddress(0), &memory, 16);
        vq.avail.idx().store(1);
        vq.avail.ring(0).store(0);
        vq.dtable(0).set(0x2000, 0x1000, 2, 0);
        memory
            .write_slice(&[0x71; 4096], GuestAddress(0x2000))
            .unwrap();
        handler.reporting = Some(VirtioQueueConfig::new(
            vq.create_queue(),
            Arc::new(EventFd::new(0).unwrap()),
            Arc::new(NoopNotifier::new()),
            2,
        ));
        let event = handler.reporting.as_ref().unwrap().eventfd.clone();
        let handler = Arc::new(Mutex::new(handler));
        let control = BalloonCaptureControl(handler.clone());
        let mut epoll = EpollManager::default();
        let subscriber = epoll.add_subscriber(Box::new(BalloonSubscriber(handler.clone())));
        let deadline = || Instant::now() + Duration::from_secs(1);
        {
            let guard = handler.lock().unwrap();
            assert!(matches!(
                control.request_hold(
                    CaptureGeneration(1),
                    Instant::now() + Duration::from_millis(5)
                ),
                Err(CaptureError::Timeout)
            ));
            assert!(!guard.capture.is_held());
        }
        let ack = control
            .request_hold(CaptureGeneration(1), deadline())
            .unwrap();
        assert_eq!(ack.memory_writers, 0);
        event.write(1).unwrap();
        epoll.handle_events(0).unwrap();
        assert_eq!(
            handler
                .lock()
                .unwrap()
                .reporting
                .as_ref()
                .unwrap()
                .queue()
                .next_used(),
            0
        );
        assert_eq!(memory.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0x71);
        assert!(control
            .resume_capture(CaptureGeneration(2), deadline())
            .is_err());
        control
            .resume_capture(CaptureGeneration(1), deadline())
            .unwrap();
        epoll.handle_events(0).unwrap();
        assert_eq!(
            handler
                .lock()
                .unwrap()
                .reporting
                .as_ref()
                .unwrap()
                .queue()
                .next_used(),
            1
        );
        assert_eq!(memory.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0);
        epoll.remove_subscriber(subscriber).unwrap();
    }

    #[test]
    fn test_balloon_page_number_to_mib() {
        assert_eq!(page_number_to_mib(1024), 4);
        assert_eq!(page_number_to_mib(1023), 3);
        assert_eq!(page_number_to_mib(0), 0);
    }

    #[test]
    fn test_balloon_mib_to_page_number() {
        assert_eq!(mib_to_page_number(4), 1024);
        assert_eq!(mib_to_page_number(2), 512);
        assert_eq!(mib_to_page_number(0), 0);
    }

    #[test]
    fn test_balloon_virtio_device_normal() {
        skip_if_kvm_unaccessable!();
        let epoll_mgr = EpollManager::default();
        let config = BalloonConfig {
            f_deflate_on_oom: true,
            f_reporting: true,
        };

        let mut dev = Balloon::<Arc<GuestMemoryMmap>>::new(epoll_mgr, config, false).unwrap();

        assert_eq!(
            VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::device_type(&dev),
            TYPE_BALLOON
        );

        let queue_size = [128, 128, 128];
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
        VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::set_acked_features(
            &mut dev, 2, 0,
        );
        assert_eq!(
            VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::get_avail_features(&dev, 2),
            0,
        );
        let config: [u8; 8] = [0; 8];
        VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::write_config(
            &mut dev, 0, &config,
        )
        .unwrap();
        let mut data: [u8; 8] = [1; 8];
        VirtioDevice::<Arc<GuestMemoryMmap<()>>, QueueSync, GuestRegionMmap>::read_config(
            &mut dev, 0, &mut data,
        )
        .unwrap();
        assert_eq!(config, data);
    }

    #[test]
    fn test_balloon_virtio_device_active() {
        skip_if_kvm_unaccessable!();
        let epoll_mgr = EpollManager::default();

        // check queue sizes error
        {
            let config = BalloonConfig {
                f_deflate_on_oom: true,
                f_reporting: true,
            };

            let mut dev =
                Balloon::<Arc<GuestMemoryMmap>>::new(epoll_mgr.clone(), config, false).unwrap();
            let queues = vec![
                VirtioQueueConfig::<QueueSync>::create(16, 0).unwrap(),
                VirtioQueueConfig::<QueueSync>::create(16, 0).unwrap(),
            ];

            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
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
            assert!(dev.activate(config).is_err());
        }
        // Success
        {
            let config = BalloonConfig {
                f_deflate_on_oom: true,
                f_reporting: true,
            };

            let mut dev = Balloon::<Arc<GuestMemoryMmap>>::new(epoll_mgr, config, false).unwrap();

            let queues = vec![
                VirtioQueueConfig::<QueueSync>::create(128, 0).unwrap(),
                VirtioQueueConfig::<QueueSync>::create(128, 0).unwrap(),
                VirtioQueueConfig::<QueueSync>::create(128, 0).unwrap(),
            ];

            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
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
            assert!(dev.activate(config).is_ok());
        }
    }

    #[test]
    fn test_balloon_set_size() {
        skip_if_kvm_unaccessable!();
        let epoll_mgr = EpollManager::default();
        let config = BalloonConfig {
            f_deflate_on_oom: true,
            f_reporting: true,
        };

        let dev = Balloon::<Arc<GuestMemoryMmap>>::new(epoll_mgr, config, false).unwrap();
        let size = 1024;
        assert!(dev.set_size(size).is_ok());
    }

    #[test]
    fn test_balloon_epoll_handler_handle_event() {
        skip_if_kvm_unaccessable!();
        let handler = create_balloon_epoll_handler();
        let event_fd = EventFd::new(0).unwrap();
        let mgr = EpollManager::default();
        let id = mgr.add_subscriber(Box::new(handler));
        let mut inner_mgr = mgr.mgr.lock().unwrap();
        let mut event_op = inner_mgr.event_ops(id).unwrap();
        let event_set = EventSet::EDGE_TRIGGERED;
        let mut handler = create_balloon_epoll_handler();

        // test for INFLATE_QUEUE_AVAIL_EVENT
        let events = Events::with_data(&event_fd, INFLATE_QUEUE_AVAIL_EVENT, event_set);
        handler.process(events, &mut event_op);

        // test for DEFLATE_QUEUE_AVAIL_EVENT
        let events = Events::with_data(&event_fd, DEFLATE_QUEUE_AVAIL_EVENT, event_set);
        handler.process(events, &mut event_op);

        // test for REPORTING_QUEUE_AVAIL_EVENT
        let events = Events::with_data(&event_fd, REPORTING_QUEUE_AVAIL_EVENT, event_set);
        handler.process(events, &mut event_op);

        // test for KILL_EVENT
        let events = Events::with_data(&event_fd, KILL_EVENT, event_set);
        handler.process(events, &mut event_op);

        // test for unknown event
        let events = Events::with_data(&event_fd, BALLOON_EVENTS_COUNT + 10, event_set);
        handler.process(events, &mut event_op);
    }

    #[test]
    fn test_balloon_epoll_handler_process_report_queue() {
        skip_if_kvm_unaccessable!();
        let mut handler = create_balloon_epoll_handler();
        let m = &handler.config.vm_as.clone();

        // Failed to get reporting queue event
        assert!(!handler.process_reporting_queue());

        // No reporting queue
        handler.reporting = None;
        assert!(!handler.process_reporting_queue());

        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let q = vq.create_queue();
        vq.avail.idx().store(1);
        vq.avail.ring(0).store(0);
        vq.dtable(0).set(0x2000, 0x1000, 0, 0);
        let queue_config = VirtioQueueConfig::new(
            q,
            Arc::new(EventFd::new(0).unwrap()),
            Arc::new(NoopNotifier::new()),
            0,
        );
        assert!(queue_config.generate_event().is_ok());
        handler.reporting = Some(queue_config);
        //Success
        assert!(handler.process_reporting_queue());
    }

    #[test]
    fn test_balloon_epoll_handler_process_queue() {
        skip_if_kvm_unaccessable!();
        let mut handler = create_balloon_epoll_handler();
        let m = &handler.config.vm_as.clone();
        // invalid idx
        {
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            let q = vq.create_queue();
            vq.avail.idx().store(1);
            vq.avail.ring(0).store(0);
            vq.dtable(0).set(0x2000, 0x1000, 0, 0);
            let queue_config = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(queue_config.generate_event().is_ok());
            handler.inflate = queue_config;
            assert!(!handler.process_queue(10));
        }
        // INFLATE_QUEUE_AVAIL_EVENT
        {
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            let q = vq.create_queue();
            vq.avail.idx().store(1);
            vq.avail.ring(0).store(0);
            vq.dtable(0).set(0x2000, 0x1000, 0, 0);
            vq.dtable(0).set(0x2000, 0x1000, 0, 0);
            let queue_config = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(queue_config.generate_event().is_ok());
            handler.inflate = queue_config;
            assert!(handler.process_queue(INFLATE_QUEUE_AVAIL_EVENT));
        }
        // DEFLATE_QUEUE_AVAIL_EVENT
        {
            let vq = VirtQueue::new(GuestAddress(0), m, 16);
            let q = vq.create_queue();
            vq.avail.idx().store(1);
            vq.avail.ring(0).store(0);
            vq.dtable(0).set(0x2000, 0x1000, 0, 0);
            let queue_config = VirtioQueueConfig::new(
                q,
                Arc::new(EventFd::new(0).unwrap()),
                Arc::new(NoopNotifier::new()),
                0,
            );
            assert!(queue_config.generate_event().is_ok());
            handler.deflate = queue_config;
            assert!(handler.process_queue(DEFLATE_QUEUE_AVAIL_EVENT));
        }
    }
}
