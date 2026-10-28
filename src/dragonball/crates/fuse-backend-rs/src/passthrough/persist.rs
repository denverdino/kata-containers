// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! State transfer for a quiesced passthrough filesystem.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Guest-visible references and negotiated options for a quiesced filesystem.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassthroughState {
    version: u32,
    preserve_file_identity: Vec<PathBuf>,
    next_inode: u64,
    next_handle: u64,
    inodes: Vec<InodeState>,
    handles: Vec<HandleState>,
    options: [bool; 7],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InodeState {
    inode: u64,
    path: Option<Vec<u8>>,
    refcount: u64,
    mode: u32,
    identity: Option<FileIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HandleState {
    handle: u64,
    inode: u64,
    flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
    generation: FileGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum FileGeneration {
    Handle(i32, Vec<u8>),
    BirthTime(i64, u32),
}

impl FileIdentity {
    fn read(file: &impl AsRawFd) -> io::Result<Self> {
        let stat = statx::statx(file, None)?;
        let empty = CString::new("").unwrap();
        let generation = if let Some(handle) = FileHandle::from_name_at(file, &empty)? {
            let (kind, bytes) = handle.identity();
            FileGeneration::Handle(kind, bytes)
        } else {
            let mut birth = std::mem::MaybeUninit::<super::os_compat::statx_st>::zeroed();
            // The kernel writes the owned buffer; fields are read only after success.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_statx,
                    file.as_raw_fd(),
                    empty.as_ptr(),
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    libc::STATX_BTIME,
                    birth.as_mut_ptr(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            // The successful statx call initialized the buffer.
            let birth = unsafe { birth.assume_init() };
            if birth.stx_mask & libc::STATX_BTIME == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "preserved files require a kernel file handle or birth time",
                ));
            }
            FileGeneration::BirthTime(birth.stx_btime.tv_sec, birth.stx_btime.tv_nsec)
        };
        Ok(Self {
            device: stat.st.st_dev,
            inode: stat.st.st_ino,
            generation,
        })
    }

    fn matches(&self, file: &File, stat: &statx::StatExt) -> io::Result<bool> {
        if self.device != stat.st.st_dev || self.inode != stat.st.st_ino {
            return Ok(false);
        }
        Ok(*self == Self::read(file)?)
    }
}

fn preserves_file(scopes: &[PathBuf], path: &[u8], mode: u32) -> bool {
    mode & libc::S_IFMT != libc::S_IFDIR
        && scopes
            .iter()
            .any(|scope| Path::new(std::ffi::OsStr::from_bytes(path)).starts_with(scope))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Resolve every component relative to an already opened directory. A guest
// symlink cannot redirect restoration outside the configured share.
fn open_relative(root: &File, path: &[u8]) -> io::Result<File> {
    let mut file = root.try_clone()?;
    let path = Path::new(std::ffi::OsStr::from_bytes(path));
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(invalid("snapshot path must be share-relative"));
        };
        let name = CString::new(name.as_bytes())?;
        file = util::openat(
            &file,
            &name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
    }
    Ok(file)
}

fn find_reference(
    root: &File,
    matches: impl Fn(&File, &statx::StatExt) -> io::Result<bool>,
) -> io::Result<Option<Vec<u8>>> {
    let mut pending = vec![(root.try_clone()?, Vec::new())];
    let mut visited = BTreeSet::new();
    while let Some((directory, prefix)) = pending.pop() {
        let id = InodeId::from_stat(&statx::statx(&directory, None)?);
        if !visited.insert(id) {
            continue;
        }
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            let name = entry?.file_name();
            let component = CString::new(name.as_bytes())?;
            let file = match util::openat(
                &directory,
                &component,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            ) {
                Ok(file) => file,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => return Err(e),
            };
            let stat = statx::statx(&file, None)?;
            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name.as_bytes());
            if matches(&file, &stat)? {
                return Ok(Some(path));
            }
            if stat.st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                pending.push((file, path));
            }
        }
    }
    Ok(None)
}

impl<S: BitmapSlice + Send + Sync> PassthroughFs<S> {
    /// Reject configurations whose backend state cannot be reconstructed.
    pub fn validate_snapshot(&self) -> io::Result<()> {
        if self.cfg.use_host_ino || self.cfg.inode_file_handles || self.cfg.dax_file_size.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "snapshot requires virtual inode IDs, path-backed inodes, and disabled DAX",
            ));
        }
        let mut scopes = BTreeSet::new();
        for scope in &self.cfg.preserve_file_identity {
            if scope.as_os_str().is_empty()
                || scope.as_os_str().as_bytes().contains(&0)
                || !scope
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                || scope
                    .as_os_str()
                    .as_bytes()
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || part == b"." || part == b"..")
                || !scopes.insert(scope)
            {
                return Err(invalid(
                    "preserved file scope must be a distinct normalized relative path",
                ));
            }
        }
        Ok(())
    }

    /// Save references after dispatch has stopped and all requests have drained.
    /// The caller must retain this exclusion until it finishes copying host files.
    pub fn save_state(&self) -> io::Result<PassthroughState> {
        self.validate_snapshot()?;
        let root_path = std::fs::canonicalize(&self.cfg.root_dir)?;
        let root = File::open(&root_path)?;
        let map = self.inode_map.inodes.read().unwrap();
        let mut inodes = Vec::new();
        for data in map.values() {
            let path = if matches!(data.handle, InodeHandle::Missing) {
                None
            } else {
                let file = data.get_file()?;
                let name = CString::new(file.as_raw_fd().to_string())?;
                let absolute = Self::readlinkat(self.proc_self_fd.as_raw_fd(), &name)?;
                match absolute.strip_prefix(&root_path) {
                    Ok(relative) => {
                        let bytes = relative.as_os_str().as_bytes();
                        match open_relative(&root, bytes) {
                            Ok(reopened) => {
                                let stat = statx::statx(&reopened, None)?;
                                if InodeId::from_stat(&stat) == data.id {
                                    Some(bytes.to_vec())
                                } else {
                                    None
                                }
                            }
                            Err(e)
                                if matches!(
                                    e.raw_os_error(),
                                    Some(libc::ENOENT | libc::ENOTDIR)
                                ) =>
                            {
                                None
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Err(_) => return Err(invalid("inode is outside the configured share")),
                }
            };
            let path = if path.is_none()
                && !matches!(data.handle, InodeHandle::Missing)
                && data.handle.stat()?.st_nlink != 0
            {
                find_reference(&root, |_, stat| Ok(InodeId::from_stat(stat) == data.id))?
            } else {
                path
            };
            let identity = match path.as_ref() {
                Some(path) if preserves_file(&self.cfg.preserve_file_identity, path, data.mode) => {
                    Some(FileIdentity::read(&data.get_file()?)?)
                }
                _ => None,
            };
            inodes.push(InodeState {
                inode: data.inode,
                path,
                refcount: data.refcount.load(Ordering::Acquire),
                mode: data.mode,
                identity,
            });
        }
        let handles = self.handle_map.handles.read().unwrap();
        let mut saved_handles = Vec::new();
        for (&handle, data) in handles.iter() {
            // F_GETFL excludes destructive creation flags such as O_TRUNC.
            let flags = unsafe { libc::fcntl(data.file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            // Linux reports its internal O_LARGEFILE bit even though libc
            // defines O_LARGEFILE as zero on x86_64. Reopening is always 64-bit.
            #[cfg(target_arch = "x86_64")]
            let flags = flags & !0o100000;
            saved_handles.push(HandleState {
                handle,
                inode: data.inode,
                flags: flags as u32,
            });
        }
        for (&handle, &inode) in self.handle_map.missing.read().unwrap().iter() {
            saved_handles.push(HandleState {
                handle,
                inode,
                flags: 0,
            });
        }
        Ok(PassthroughState {
            version: 2,
            preserve_file_identity: self.cfg.preserve_file_identity.clone(),
            next_inode: self.next_inode.load(Ordering::Acquire),
            next_handle: self.next_handle.load(Ordering::Acquire),
            inodes,
            handles: saved_handles,
            options: [
                self.writeback.load(Ordering::Acquire),
                self.no_open.load(Ordering::Acquire),
                self.no_opendir.load(Ordering::Acquire),
                self.killpriv_v2.load(Ordering::Acquire),
                self.no_readdir.load(Ordering::Acquire),
                self.seal_size.load(Ordering::Acquire),
                self.perfile_dax.load(Ordering::Acquire),
            ],
        })
    }

    /// Rebuild references in an unused backend before accepting guest requests.
    /// Host inode numbers may differ after extracting the saved filesystem tree.
    pub fn restore_state(&self, state: &PassthroughState) -> io::Result<()> {
        self.validate_snapshot()?;
        if state.version != 2
            || state.preserve_file_identity != self.cfg.preserve_file_identity
            || state.next_inode <= fuse::ROOT_ID
            || state.next_handle == 0
            || state.next_inode > VFS_MAX_INO
        {
            return Err(invalid("unsupported passthrough snapshot"));
        }
        let root = File::open(&self.cfg.root_dir)?;
        let mut inodes = InodeStore::default();
        let mut ids = BTreeSet::new();
        let mut host_ids = BTreeSet::new();
        for entry in &state.inodes {
            if entry.inode == 0
                || entry.inode >= state.next_inode
                || entry.refcount == 0
                || !ids.insert(entry.inode)
            {
                return Err(invalid("invalid or duplicate snapshot inode"));
            }
            if entry.inode == fuse::ROOT_ID && entry.path.as_deref() != Some(&[]) {
                return Err(invalid("snapshot root is missing"));
            }
            let requires_identity = entry.path.as_ref().is_some_and(|path| {
                preserves_file(&self.cfg.preserve_file_identity, path, entry.mode)
            });
            if requires_identity != entry.identity.is_some() {
                return Err(invalid("snapshot file identity does not match its scope"));
            }
            let mut reopened = entry
                .path
                .as_ref()
                .map(|path| open_relative(&root, path))
                .transpose();
            if let Some(identity) = &entry.identity {
                let matches = match &reopened {
                    Ok(Some(file)) => identity.matches(file, &statx::statx(file, None)?)?,
                    Ok(None) => false,
                    Err(error)
                        if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) =>
                    {
                        false
                    }
                    Err(_) => return Err(reopened.err().unwrap()),
                };
                if !matches {
                    reopened = find_reference(&root, |file, stat| identity.matches(file, stat))?
                        .map(|path| open_relative(&root, &path))
                        .transpose();
                }
            }
            let (handle, id, mode) = match reopened {
                Ok(Some(file)) => {
                    let stat = statx::statx(&file, None)?;
                    // A live tree may change between finding a path and opening it.
                    let matches = match &entry.identity {
                        Some(identity) => identity.matches(&file, &stat)?,
                        None => true,
                    };
                    if !matches {
                        (InodeHandle::Missing, InodeId::default(), entry.mode)
                    } else {
                        if stat.st.st_mode & libc::S_IFMT != entry.mode & libc::S_IFMT {
                            return Err(invalid("snapshot inode changed file type"));
                        }
                        let id = InodeId::from_stat(&stat);
                        if !host_ids.insert(id) {
                            return Err(invalid("snapshot inodes alias one host file"));
                        }
                        (InodeHandle::File(file), id, stat.st.st_mode)
                    }
                }
                Ok(None) => (InodeHandle::Missing, InodeId::default(), entry.mode),
                Err(e)
                    if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
                        && entry.inode != fuse::ROOT_ID =>
                {
                    (InodeHandle::Missing, InodeId::default(), entry.mode)
                }
                Err(e) => return Err(e),
            };
            inodes.insert(Arc::new(InodeData::new(
                entry.inode,
                handle,
                entry.refcount,
                id,
                mode,
            )));
        }
        if !ids.contains(&fuse::ROOT_ID) {
            return Err(invalid("snapshot root is missing"));
        }
        let mut handles = BTreeMap::new();
        let mut missing = BTreeMap::new();
        let mut handle_ids = BTreeSet::new();
        for entry in &state.handles {
            if entry.handle == 0
                || entry.handle >= state.next_handle
                || !handle_ids.insert(entry.handle)
            {
                return Err(invalid("invalid or duplicate snapshot handle"));
            }
            let inode = inodes
                .get(&entry.inode)
                .ok_or_else(|| invalid("snapshot handle has no inode"))?;
            if matches!(inode.handle, InodeHandle::Missing) {
                missing.insert(entry.handle, entry.inode);
            } else {
                let allowed = libc::O_ACCMODE
                    | libc::O_APPEND
                    | libc::O_NONBLOCK
                    | libc::O_DSYNC
                    | libc::O_SYNC
                    | libc::O_DIRECT
                    | libc::O_LARGEFILE
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NOATIME;
                if entry.flags as i32 & !allowed != 0 {
                    return Err(invalid("unsupported snapshot open flags"));
                }
                if !is_safe_inode(inode.mode) {
                    return Err(invalid("unsafe snapshot handle type"));
                }
                let file =
                    inode.open_file(entry.flags as i32 | libc::O_CLOEXEC, &self.proc_self_fd)?;
                handles.insert(
                    entry.handle,
                    Arc::new(HandleData::new(entry.inode, file, entry.flags)),
                );
            }
        }
        *self.inode_map.inodes.write().unwrap() = inodes;
        *self.handle_map.handles.write().unwrap() = handles;
        *self.handle_map.missing.write().unwrap() = missing;
        self.next_inode.store(state.next_inode, Ordering::Release);
        self.next_handle.store(state.next_handle, Ordering::Release);
        let options = [
            &self.writeback,
            &self.no_open,
            &self.no_opendir,
            &self.killpriv_v2,
            &self.no_readdir,
            &self.seal_size,
            &self.perfile_dax,
        ];
        for (option, value) in options.iter().zip(state.options.iter().copied()) {
            option.store(value, Ordering::Release);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Config, PassthroughFs};
    use crate::api::filesystem::{Context, FileSystem, FsOptions, ZeroCopyWriter};
    use crate::file_buf::FileVolatileSlice;
    use crate::file_traits::FileReadWriteVolatile;
    use std::ffi::CString;
    use std::io::{self, Write};
    use std::path::PathBuf;
    use vmm_sys_util::tempdir::TempDir;

    #[derive(Default)]
    struct Output(Vec<u8>);

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ZeroCopyWriter for Output {
        fn available_bytes(&self) -> usize {
            usize::MAX
        }
        fn write_from(
            &mut self,
            file: &mut dyn FileReadWriteVolatile,
            count: usize,
            offset: u64,
        ) -> io::Result<usize> {
            let mut buf = vec![0; count];
            // The buffer stays allocated and exclusively borrowed during the read.
            let slice = unsafe { FileVolatileSlice::from_mut_slice(&mut buf) };
            let len = file.read_at_volatile(slice, offset)?;
            self.0.extend_from_slice(&buf[..len]);
            Ok(len)
        }
    }

    fn filesystem(root: &std::path::Path) -> PassthroughFs<()> {
        scoped_filesystem(root, Vec::new())
    }

    fn scoped_filesystem(root: &std::path::Path, scopes: Vec<PathBuf>) -> PassthroughFs<()> {
        let fs = PassthroughFs::new(Config {
            preserve_file_identity: scopes,
            root_dir: root.to_str().unwrap().into(),
            xattr: true,
            ..Default::default()
        })
        .unwrap();
        fs.import().unwrap();
        fs.init(FsOptions::empty()).unwrap();
        fs
    }

    #[test]
    fn restored_live_handles_keep_object_identity() {
        for change in ["replace", "same-content", "write", "rename", "adjacent"] {
            let root = TempDir::new().unwrap();
            let directory = if change == "adjacent" {
                "live-other"
            } else {
                "live"
            };
            std::fs::create_dir(root.as_path().join(directory)).unwrap();
            let path = root.as_path().join(directory).join("file");
            std::fs::write(&path, b"original").unwrap();
            let scopes = vec![PathBuf::from("live")];
            let fs = scoped_filesystem(root.as_path(), scopes.clone());
            let ctx = Context::default();
            let parent = fs
                .lookup(&ctx, 1, &CString::new(directory).unwrap())
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
            if change == "write" {
                std::fs::write(&path, b"updated!").unwrap();
            } else {
                if change == "rename" {
                    std::fs::hard_link(&path, path.with_file_name("alias")).unwrap();
                }
                let contents: &[u8] = if change == "same-content" {
                    b"original"
                } else {
                    b"replaced"
                };
                std::fs::write(path.with_file_name("new"), contents).unwrap();
                std::fs::rename(path.with_file_name("new"), &path).unwrap();
            }
            let restored = scoped_filesystem(root.as_path(), scopes);
            let mut omitted = state.clone();
            omitted.preserve_file_identity.clear();
            assert!(restored.restore_state(&omitted).is_err());
            if change != "adjacent" {
                let mut omitted = state.clone();
                omitted
                    .inodes
                    .iter_mut()
                    .find(|entry| entry.inode == inode)
                    .unwrap()
                    .identity = None;
                assert!(restored.restore_state(&omitted).is_err());
            }
            restored.restore_state(&state).unwrap();
            let mut output = Output::default();
            let result = restored.read(&ctx, inode, handle, &mut output, 8, 0, None, 0);
            match change {
                "replace" | "same-content" => {
                    assert_eq!(
                        result.unwrap_err().raw_os_error(),
                        Some(libc::EIO),
                        "{change}"
                    );
                    assert!(output.0.is_empty());
                    let new_inode = restored
                        .lookup(&ctx, parent, &CString::new("file").unwrap())
                        .unwrap()
                        .inode;
                    assert_ne!(new_inode, inode);
                }
                _ => {
                    result.unwrap();
                    let expected: &[u8] = match change {
                        "write" => b"updated!",
                        "rename" => b"original",
                        _ => b"replaced",
                    };
                    assert_eq!(output.0, expected, "{change}");
                }
            }
        }
    }

    #[test]
    fn preserved_scopes_reject_ambiguous_paths() {
        let root = TempDir::new().unwrap();
        for scope in [
            "",
            "/live",
            "../live",
            "live/../other",
            "live/",
            "live//child",
            "./live",
            "live\0name",
        ] {
            let fs = scoped_filesystem(root.as_path(), vec![PathBuf::from(scope)]);
            assert!(fs.save_state().is_err(), "{scope}");
        }
        let fs = scoped_filesystem(
            root.as_path(),
            vec![PathBuf::from("live"), PathBuf::from("live")],
        );
        assert!(fs.save_state().is_err());
    }

    #[test]
    fn restore_open_handle_after_recreating_host_tree() {
        let original = TempDir::new().unwrap();
        std::fs::write(original.as_path().join("file"), b"before:payload").unwrap();
        let fs = filesystem(original.as_path());
        assert!(fs
            .init(FsOptions::PERFILE_DAX)
            .unwrap()
            .contains(FsOptions::PERFILE_DAX));
        let ctx = Context::default();
        let entry = fs.lookup(&ctx, 1, &CString::new("file").unwrap()).unwrap();
        let handle = fs
            .open(&ctx, entry.inode, libc::O_RDONLY as u32, 0)
            .unwrap()
            .0
            .unwrap();
        let state = fs.save_state().unwrap();
        drop(fs);
        let restored = TempDir::new().unwrap();
        std::fs::write(restored.as_path().join("file"), b"before:payload").unwrap();
        let fs = filesystem(restored.as_path());
        fs.restore_state(&state).unwrap();
        let mut out = Output::default();
        fs.read(
            &ctx,
            entry.inode,
            handle,
            &mut out,
            7,
            7,
            None,
            libc::O_RDONLY as u32,
        )
        .unwrap();
        assert_eq!(out.0, b"payload");
        assert_eq!(
            fs.lookup(&ctx, 1, &CString::new("file").unwrap())
                .unwrap()
                .inode,
            entry.inode
        );
        std::fs::write(restored.as_path().join("new"), b"new").unwrap();
        assert_ne!(
            fs.lookup(&ctx, 1, &CString::new("new").unwrap())
                .unwrap()
                .inode,
            entry.inode
        );
    }
    #[test]
    fn restore_referenced_hardlink_after_unlinking_original_name() {
        let root = TempDir::new().unwrap();
        std::fs::write(root.as_path().join("file"), b"payload").unwrap();
        std::fs::hard_link(root.as_path().join("file"), root.as_path().join("alias")).unwrap();
        let fs = filesystem(root.as_path());
        let ctx = Context::default();
        let inode = fs
            .lookup(&ctx, 1, &CString::new("file").unwrap())
            .unwrap()
            .inode;
        let handle = fs
            .open(&ctx, inode, libc::O_RDONLY as u32, 0)
            .unwrap()
            .0
            .unwrap();
        std::fs::remove_file(root.as_path().join("file")).unwrap();
        let state = fs.save_state().unwrap();
        drop(fs);
        let fs = filesystem(root.as_path());
        fs.restore_state(&state).unwrap();
        let mut out = Output::default();
        fs.read(&ctx, inode, handle, &mut out, 7, 0, None, 0)
            .unwrap();
        assert_eq!(out.0, b"payload");
    }
    #[test]
    fn missing_handle_does_not_attach_to_replacement() {
        let root = TempDir::new().unwrap();
        let file = root.as_path().join("file");
        std::fs::write(&file, b"old").unwrap();
        let fs = filesystem(root.as_path());
        let ctx = Context::default();
        let name = CString::new("file").unwrap();
        let inode = fs.lookup(&ctx, 1, &name).unwrap().inode;
        let handle = fs.open(&ctx, inode, 0, 0).unwrap().0.unwrap();
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, b"replacement").unwrap();
        let state = fs.save_state().unwrap();
        drop(fs);
        let fs = filesystem(root.as_path());
        fs.restore_state(&state).unwrap();
        let error = fs
            .read(&ctx, inode, handle, &mut Output::default(), 3, 0, None, 0)
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_ne!(fs.lookup(&ctx, 1, &name).unwrap().inode, inode);
        let state = fs.save_state().unwrap();
        drop(fs);
        let fs = filesystem(root.as_path());
        fs.restore_state(&state).unwrap();
        assert_eq!(
            fs.getattr(&ctx, inode, Some(handle))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
    }

    #[test]
    fn renamed_file_retains_handle_and_xattr() {
        use crate::api::filesystem::GetxattrReply;
        let root = TempDir::new().unwrap();
        std::fs::write(root.as_path().join("file"), b"payload").unwrap();
        let fs = filesystem(root.as_path());
        let ctx = Context::default();
        let old = CString::new("file").unwrap();
        let new = CString::new("renamed").unwrap();
        let key = CString::new("user.snapshot").unwrap();
        let inode = fs.lookup(&ctx, 1, &old).unwrap().inode;
        let handle = fs.open(&ctx, inode, 0, 0).unwrap().0.unwrap();
        fs.setxattr(&ctx, inode, &key, b"value", 0).unwrap();
        fs.rename(&ctx, 1, &old, 1, &new, 0).unwrap();
        let state = fs.save_state().unwrap();
        drop(fs);
        let fs = filesystem(root.as_path());
        fs.restore_state(&state).unwrap();
        let mut out = Output::default();
        fs.read(&ctx, inode, handle, &mut out, 7, 0, None, 0)
            .unwrap();
        assert_eq!(out.0, b"payload");
        assert_eq!(fs.lookup(&ctx, 1, &new).unwrap().inode, inode);
        match fs.getxattr(&ctx, inode, &key, 5).unwrap() {
            GetxattrReply::Value(value) => assert_eq!(value, b"value"),
            _ => panic!("expected xattr value"),
        }
    }

    #[test]
    fn restore_rejects_escape_paths_and_destructive_flags() {
        let root = TempDir::new().unwrap();
        std::fs::write(root.as_path().join("file"), b"unchanged").unwrap();
        let fs = filesystem(root.as_path());
        let ctx = Context::default();
        let inode = fs
            .lookup(&ctx, 1, &CString::new("file").unwrap())
            .unwrap()
            .inode;
        fs.open(&ctx, inode, libc::O_RDWR as u32, 0).unwrap();
        let state = fs.save_state().unwrap();
        let json = serde_json::to_value(&state).unwrap();
        for path in [b"../file".as_slice(), b"/file".as_slice()] {
            let mut value = json.clone();
            value["inodes"][1]["path"] = serde_json::to_value(path).unwrap();
            let corrupt = serde_json::from_value(value).unwrap();
            assert!(filesystem(root.as_path()).restore_state(&corrupt).is_err());
        }
        let mut value = json;
        value["handles"][0]["flags"] = serde_json::json!(libc::O_RDWR | libc::O_TRUNC);
        let corrupt = serde_json::from_value(value).unwrap();
        assert!(filesystem(root.as_path()).restore_state(&corrupt).is_err());
        assert_eq!(
            std::fs::read(root.as_path().join("file")).unwrap(),
            b"unchanged"
        );
    }
    #[test]
    fn restored_directory_references_allow_lookup_and_readdir() {
        let original = TempDir::new().unwrap();
        std::fs::create_dir(original.as_path().join("dir")).unwrap();
        std::fs::write(original.as_path().join("dir/file"), b"payload").unwrap();
        let fs = filesystem(original.as_path());
        let ctx = Context::default();
        let directory = fs
            .lookup(&ctx, 1, &CString::new("dir").unwrap())
            .unwrap()
            .inode;
        let child = fs
            .lookup(&ctx, directory, &CString::new("file").unwrap())
            .unwrap()
            .inode;
        let handle = fs.opendir(&ctx, directory, 0).unwrap().0.unwrap();
        let state = fs.save_state().unwrap();
        drop(fs);
        let root = TempDir::new().unwrap();
        std::fs::create_dir(root.as_path().join("dir")).unwrap();
        std::fs::write(root.as_path().join("dir/file"), b"payload").unwrap();
        let fs = filesystem(root.as_path());
        fs.restore_state(&state).unwrap();
        assert_eq!(
            fs.lookup(&ctx, directory, &CString::new("file").unwrap())
                .unwrap()
                .inode,
            child
        );
        let mut names = Vec::new();
        fs.readdir(&ctx, directory, handle, 4096, 0, &mut |entry| {
            names.push(entry.name.to_vec());
            Ok(1)
        })
        .unwrap();
        assert!(names.iter().any(|name| name == b"file"));
        let next_handle = fs.open(&ctx, child, 0, 0).unwrap().0.unwrap();
        assert_ne!(next_handle, handle);
        std::fs::write(root.as_path().join("dir/other"), b"other").unwrap();
        let next_inode = fs
            .lookup(&ctx, directory, &CString::new("other").unwrap())
            .unwrap()
            .inode;
        assert_ne!(next_inode, child);
        assert_ne!(next_inode, directory);
    }
}
