fn main() {
    // Compiling a real external consumer must not depend on runtime-rs features.
    let _ = std::mem::size_of::<dragonball::api::v1::VmmAction>();
    #[cfg(target_arch = "x86_64")]
    let _ = capture_actions;
}

#[cfg(target_arch = "x86_64")]
fn capture_actions(files: dragonball::snapshot::capture::SnapshotFiles) {
    use dragonball::api::v1::{VmmAction, VmmData};
    use dragonball::snapshot::capture::{CaptureReport, MemoryLayout};
    let deadline = std::time::Instant::now();
    let _ = VmmAction::BeginCapture {
        generation: 1,
        deadline,
    };
    let _ = VmmAction::LoadSnapshotHeld {
        generation: 1,
        deadline,
        files: files.clone(),
    };
    let _ = VmmAction::ExportHeldSnapshot {
        generation: 1,
        deadline,
        files,
    };
    let _ = VmmAction::EndCapture {
        generation: 1,
        deadline,
        resume: true,
    };
    let _ = VmmData::CaptureReport(CaptureReport {
        generation: 1,
        vcpu_acks: Vec::new(),
        device_acks: Vec::new(),
        memory_layout: MemoryLayout {
            regions: Vec::new(),
            total_bytes: 0,
        },
    });
}
