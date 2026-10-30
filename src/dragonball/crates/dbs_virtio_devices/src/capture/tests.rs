// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::time::Duration;

#[test]
fn disconnected_waiter_does_not_release_or_relabel_a_hold() {
    let mut gate = CaptureGate::new("device".into());
    let limit = Instant::now() + Duration::from_secs(1);
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(1), limit, reply);
    drop(receiver);
    gate.finish(Ok(()));
    assert!(gate.is_held());
    assert_eq!(
        gate.release(CaptureGeneration(2)),
        Err(CaptureError::StaleGeneration)
    );
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(2), limit, reply);
    assert_eq!(receiver.recv().unwrap(), Err(CaptureError::StaleGeneration));
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(1), limit, reply);
    assert_eq!(receiver.recv().unwrap().unwrap().generation, 1);
    assert!(gate.release(CaptureGeneration(1)).unwrap());
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(2), limit, reply);
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    gate.finish(Ok(()));
    assert_eq!(receiver.recv().unwrap().unwrap().generation, 2);
}

#[test]
fn failed_drain_is_retained_and_stale_generations_remain_rejected() {
    let mut gate = CaptureGate::new("device".into());
    let limit = Instant::now() + Duration::from_secs(1);
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(1), limit, reply);
    gate.finish(Err(std::io::Error::from_raw_os_error(libc::ENOSPC)));
    assert!(matches!(
        receiver.recv().unwrap(),
        Err(CaptureError::FlushFailed(_))
    ));
    assert!(gate.is_held());
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(1), limit, reply);
    assert!(matches!(
        receiver.recv().unwrap(),
        Err(CaptureError::FlushFailed(_))
    ));
    gate.release(CaptureGeneration(1)).unwrap();
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(1), limit, reply);
    assert_eq!(receiver.recv().unwrap(), Err(CaptureError::StaleGeneration));
    let (reply, receiver) = mpsc::channel();
    gate.begin(CaptureGeneration(2), limit, reply);
    gate.finish(Ok(()));
    assert_eq!(receiver.recv().unwrap().unwrap().generation, 2);
}
