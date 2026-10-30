// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::*;

fn descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn backend_large_restore_failure_is_atomic_and_releases_opened_files() {
    const NAME: &str = "passthrough::persist::tests::hardening::backend_large_restore_failure_is_atomic_and_releases_opened_files";
    if std::env::var_os("KATA_FS_RESOURCE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env("KATA_FS_RESOURCE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let root = TempDir::new().unwrap();
    let fs = filesystem(root.as_path());
    let ctx = Context::default();
    let mut references = Vec::new();
    let mut original_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // This isolated child owns the limit and the initialized output buffer.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original_limit) },
        0
    );
    let count = 512.min((original_limit.rlim_cur as usize).saturating_sub(descriptors() + 32) / 4);
    assert!(
        count >= 16,
        "insufficient descriptors for restore pressure qualification"
    );
    for index in 0..count {
        let name = format!("file-{:04}", index);
        std::fs::write(root.as_path().join(&name), index.to_string()).unwrap();
        let entry = fs.lookup(&ctx, 1, &CString::new(name).unwrap()).unwrap();
        let handle = fs
            .open(&ctx, entry.inode, libc::O_RDONLY as u32, 0)
            .unwrap()
            .0
            .unwrap();
        references.push((entry.inode, handle, index.to_string()));
    }
    let state = fs.save_state().unwrap();
    drop(fs);
    let base = descriptors();
    let target = filesystem(root.as_path());
    let opened = descriptors();
    let pressure = libc::rlimit {
        rlim_cur: (opened + count + 8) as libc::rlim_t,
        rlim_max: original_limit.rlim_max,
    };
    // Only this child process is constrained; the caller and host are unchanged.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &pressure) },
        0
    );
    let result = target.restore_state(&state);
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original_limit) },
        0
    );
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EMFILE));
    assert_eq!(descriptors(), opened);
    assert_eq!(target.save_state().unwrap().inodes.len(), 1);
    drop(target);
    assert_eq!(descriptors(), base);
    for trial in 0..32 {
        let target = filesystem(root.as_path());
        let opened = descriptors();
        let mut bad = state.clone();
        match trial % 4 {
            0 => bad.handles.last_mut().unwrap().flags |= libc::O_TRUNC as u32,
            1 => bad.handles.last_mut().unwrap().inode = state.next_inode,
            2 => bad.handles.last_mut().unwrap().handle = state.handles[0].handle,
            _ => bad.inodes.last_mut().unwrap().inode = state.inodes[0].inode,
        }
        assert!(
            target.restore_state(&bad).is_err(),
            "mutation {} accepted",
            trial
        );
        assert_eq!(descriptors(), opened, "failed restore leaked descriptors");
        assert_eq!(
            target.save_state().unwrap().inodes.len(),
            1,
            "failed restore changed the original inode store"
        );
        target.restore_state(&state).unwrap();
        for &(inode, handle, ref expected) in references.iter().step_by(31) {
            let mut output = Output::default();
            target
                .read(&ctx, inode, handle, &mut output, 16, 0, None, 0)
                .unwrap();
            assert_eq!(&output.0, expected.as_bytes());
        }
        drop(target);
        assert_eq!(
            descriptors(),
            base,
            "successful restore/drop leaked descriptors"
        );
    }
}

#[test]
fn backend_combined_live_rename_unlink_and_replacement_keeps_identity() {
    for retain_original in [false, true] {
        let root = TempDir::new().unwrap();
        let live = root.as_path().join("live");
        std::fs::create_dir_all(live.join("nested")).unwrap();
        std::fs::write(live.join("file"), b"original").unwrap();
        std::fs::hard_link(live.join("file"), live.join("alias")).unwrap();
        let scopes = vec![PathBuf::from("live")];
        let fs = scoped_filesystem(root.as_path(), scopes.clone());
        let ctx = Context::default();
        let parent = fs
            .lookup(&ctx, 1, &CString::new("live").unwrap())
            .unwrap()
            .inode;
        let inode = fs
            .lookup(&ctx, parent, &CString::new("file").unwrap())
            .unwrap()
            .inode;
        let handle = fs
            .open(&ctx, inode, libc::O_RDONLY as u32, 0)
            .unwrap()
            .0
            .unwrap();
        let state = fs.save_state().unwrap();
        drop(fs);
        std::fs::rename(live.join("alias"), live.join("nested/moved")).unwrap();
        std::fs::write(live.join("replacement"), b"replaced").unwrap();
        std::fs::rename(live.join("replacement"), live.join("file")).unwrap();
        if retain_original {
            std::fs::write(live.join("nested/moved"), b"updated!").unwrap();
        } else {
            std::fs::remove_file(live.join("nested/moved")).unwrap();
        }
        let target = scoped_filesystem(root.as_path(), scopes);
        target.restore_state(&state).unwrap();
        let mut output = Output::default();
        let result = target.read(&ctx, inode, handle, &mut output, 8, 0, None, 0);
        if retain_original {
            result.unwrap();
            assert_eq!(output.0, b"updated!");
        } else {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
            assert!(output.0.is_empty());
        }
        let current = target
            .lookup(&ctx, parent, &CString::new("file").unwrap())
            .unwrap()
            .inode;
        assert_ne!(current, inode);
    }
}
