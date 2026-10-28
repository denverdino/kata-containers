// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::time::Instant;

use dbs_utils::epoll_manager::{EventOps, Events, MutEventSubscriber};
use virtio_queue::QueueT;
use vm_memory::{GuestAddressSpace, GuestMemoryRegion};

use super::handler::VirtioFsEpollHandler;
use crate::capture::{CaptureError, CaptureGeneration, CaptureResult, WorkerAck};

pub(crate) struct FsSubscriber<T>(pub(crate) Arc<Mutex<T>>);

impl<T: MutEventSubscriber> MutEventSubscriber for FsSubscriber<T> {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        self.0
            .lock()
            .expect("fs handler lock poisoned")
            .process(events, ops);
    }
    fn init(&mut self, ops: &mut EventOps) {
        self.0.lock().expect("fs handler lock poisoned").init(ops);
    }
}

pub(crate) trait FsCaptureController: Send {
    fn hold(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<WorkerAck>;
    fn resume(&mut self, generation: CaptureGeneration) -> CaptureResult<()>;
    fn held(&self) -> bool;
}

/// Capture control for a synchronous inline filesystem handler.
#[derive(Clone)]
pub struct FsCaptureControl(pub(crate) Arc<Mutex<dyn FsCaptureController>>);

impl FsCaptureControl {
    fn with_handler<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce(&mut dyn FsCaptureController) -> CaptureResult<T>,
    ) -> CaptureResult<T> {
        loop {
            if Instant::now() >= deadline {
                return Err(CaptureError::Timeout);
            }
            match self.0.try_lock() {
                Ok(mut handler) => return operation(&mut *handler),
                Err(TryLockError::Poisoned(_)) => return Err(CaptureError::Disconnected),
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            }
        }
    }

    /// Wait for the current request to finish, then stop subsequent dispatch.
    pub fn request_hold(
        &self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<WorkerAck> {
        self.with_handler(deadline, |handler| handler.hold(generation, deadline))
    }

    /// Release only the matching generation and kick all queues.
    pub fn resume_capture(
        &self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<()> {
        self.with_handler(deadline, |handler| handler.resume(generation))
    }

    pub(crate) fn is_held(&self) -> CaptureResult<bool> {
        self.0
            .lock()
            .map(|handler| handler.held())
            .map_err(|_| CaptureError::Disconnected)
    }
}

impl<AS, Q, R> FsCaptureController for VirtioFsEpollHandler<AS, Q, R>
where
    AS: GuestAddressSpace + Clone + Send + 'static,
    AS::T: Send,
    AS::M: Sync + Send,
    Q: QueueT + Send + 'static,
    R: GuestMemoryRegion + Send + Sync + 'static,
{
    fn hold(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<WorkerAck> {
        // Pooled requests retain guest memory beyond this handler's lock.
        if self.thread_pool.is_some() {
            return Err(CaptureError::Disconnected);
        }
        let (reply, receiver) = mpsc::channel();
        self.capture.begin(generation, deadline, reply);
        if self.capture.needs_ack() {
            self.capture.finish_report(Ok(self.capture.held_ack(false)));
        }
        receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| CaptureError::Timeout)?
    }

    fn resume(&mut self, generation: CaptureGeneration) -> CaptureResult<()> {
        if self.capture.release(generation)? {
            for queue in &self.config.lock().unwrap().queues {
                queue
                    .eventfd
                    .write(1)
                    .map_err(|e| CaptureError::ControlIo(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn held(&self) -> bool {
        self.capture.is_held() && self.thread_pool.is_none()
    }
}
