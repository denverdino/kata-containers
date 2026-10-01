// SPDX-License-Identifier: Apache-2.0

//! Worker-side capture barriers. A caller timeout never releases a barrier.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Instant;

use vmm_sys_util::eventfd::EventFd;

/// A nonzero, monotonically increasing capture generation within one VM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureGeneration(pub u64);

/// Evidence returned only after a worker has stopped writing guest memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerAck {
    pub device_id: String,
    pub generation: u64,
    pub pending_io: u64,
    pub memory_writers: u32,
    pub flush_completed: bool,
}

/// Capture errors do not imply that the worker has resumed.
#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum CaptureError {
    #[error("capture control deadline exceeded; worker state must be confirmed")]
    Timeout,
    #[error("capture worker disconnected")]
    Disconnected,
    #[error("capture generation is zero, stale, or belongs to another hold")]
    StaleGeneration,
    #[error("capture barrier was released before drain completed")]
    Released,
    #[error("too many pending capture confirmations")]
    TooManyWaiters,
    #[error("capture flush failed: {0}")]
    FlushFailed(String),
    #[error("capture control eventfd failed: {0}")]
    ControlIo(String),
}

pub type CaptureResult<T> = std::result::Result<T, CaptureError>;

pub(crate) enum WorkerCommand {
    Hold {
        generation: CaptureGeneration,
        deadline: Instant,
        reply: Sender<CaptureResult<WorkerAck>>,
    },
    Resume {
        generation: CaptureGeneration,
        deadline: Instant,
        reply: Sender<CaptureResult<()>>,
    },
}

/// A channel and eventfd endpoint; waiting does not lock the device or queue.
#[derive(Clone)]
pub struct WorkerCaptureControl {
    pub(crate) sender: Sender<WorkerCommand>,
    pub(crate) wake: Arc<EventFd>,
}

impl WorkerCaptureControl {
    pub(crate) fn new(wake: EventFd) -> (Self, Receiver<WorkerCommand>) {
        let (sender, receiver) = mpsc::channel();
        (
            Self {
                sender,
                wake: Arc::new(wake),
            },
            receiver,
        )
    }

    pub fn request_hold(
        &self,
        generation: CaptureGeneration,
        deadline: Instant,
    ) -> CaptureResult<WorkerAck> {
        let (reply, receiver) = mpsc::channel();
        if deadline <= Instant::now() {
            return Err(CaptureError::Timeout);
        }
        self.send(WorkerCommand::Hold {
            generation,
            deadline,
            reply,
        })?;
        Self::wait(receiver, deadline)
    }

    pub fn resume(&self, generation: CaptureGeneration, deadline: Instant) -> CaptureResult<()> {
        let (reply, receiver) = mpsc::channel();
        if deadline <= Instant::now() {
            return Err(CaptureError::Timeout);
        }
        self.send(WorkerCommand::Resume {
            generation,
            deadline,
            reply,
        })?;
        Self::wait(receiver, deadline)
    }

    fn send(&self, command: WorkerCommand) -> CaptureResult<()> {
        self.sender
            .send(command)
            .map_err(|_| CaptureError::Disconnected)?;
        self.wake
            .write(1)
            .map_err(|e| CaptureError::ControlIo(e.to_string()))
    }

    fn wait<T>(receiver: Receiver<CaptureResult<T>>, deadline: Instant) -> CaptureResult<T> {
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => Err(CaptureError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(CaptureError::Disconnected),
        }
    }
}

/// Worker-owned state, accessed only on its event-loop thread.
pub(crate) struct CaptureGate {
    device_id: String,
    generation: Option<CaptureGeneration>,
    last_generation: u64,
    completed: Option<CaptureResult<WorkerAck>>,
    waiters: Vec<Sender<CaptureResult<WorkerAck>>>,
}

impl CaptureGate {
    pub(crate) fn new(device_id: String) -> Self {
        Self {
            device_id,
            generation: None,
            last_generation: 0,
            completed: None,
            waiters: Vec::new(),
        }
    }

    pub(crate) fn is_held(&self) -> bool {
        self.generation.is_some()
    }

    pub(crate) fn needs_ack(&self) -> bool {
        self.is_held() && self.completed.is_none()
    }

    pub(crate) fn begin(
        &mut self,
        generation: CaptureGeneration,
        deadline: Instant,
        reply: Sender<CaptureResult<WorkerAck>>,
    ) {
        if deadline <= Instant::now() {
            let _ = reply.send(Err(CaptureError::Timeout));
        } else if self.generation == Some(generation) {
            if let Some(result) = &self.completed {
                let _ = reply.send(result.clone());
            } else if self.waiters.len() < 16 {
                self.waiters.push(reply);
            } else {
                let _ = reply.send(Err(CaptureError::TooManyWaiters));
            }
        } else if generation.0 == 0 || self.is_held() || generation.0 <= self.last_generation {
            let _ = reply.send(Err(CaptureError::StaleGeneration));
        } else {
            self.last_generation = generation.0;
            self.generation = Some(generation);
            self.completed = None;
            self.waiters.push(reply);
        }
    }

    pub(crate) fn finish(&mut self, flush: std::io::Result<()>) {
        let result = flush
            .map(|()| self.held_ack(true))
            .map_err(|e| CaptureError::FlushFailed(e.to_string()));
        self.finish_report(result);
    }

    pub(crate) fn held_ack(&self, flush_completed: bool) -> WorkerAck {
        WorkerAck {
            device_id: self.device_id.clone(),
            generation: self.generation.expect("ack requires a held worker").0,
            pending_io: 0,
            memory_writers: 0,
            flush_completed,
        }
    }

    pub(crate) fn finish_report(&mut self, result: CaptureResult<WorkerAck>) {
        for waiter in self.waiters.drain(..) {
            let _ = waiter.send(result.clone());
        }
        self.completed = Some(result);
    }

    pub(crate) fn release(&mut self, generation: CaptureGeneration) -> CaptureResult<bool> {
        if generation.0 == 0 || generation.0 != self.last_generation {
            return Err(CaptureError::StaleGeneration);
        }
        if self.generation.is_none() {
            return Ok(false);
        }
        self.generation = None;
        self.completed = None;
        for waiter in self.waiters.drain(..) {
            let _ = waiter.send(Err(CaptureError::Released));
        }
        Ok(true)
    }
}
