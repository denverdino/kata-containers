# Local changes

This copy comes from fuse-backend-rs 0.14.0 on crates.io. Its archive SHA-256 is
`13d8148185e731fa601a078e4ae8c742bf4b69e86e19136848780deaef08fd7d`.

The `persist` feature adds passthrough state transfer for Dragonball snapshots.
It preserves guest references across reconstructed host files and records missing
references as EIO. Callers must quiesce requests before saving or restoring.
Snapshot support excludes DAX and host-derived inode IDs. Directory references
can resume lookup and enumeration from offset zero. Nonzero directory cookies
remain host filesystem cookies; continuity after rebuilding a directory has not
been qualified.

The workspace patch also applies this copy to Nydus so both consumers use the
same filesystem types. Original license files and source headers are retained.
