fn main() {
    // Compiling a real external consumer must not depend on runtime-rs features.
    let _ = std::mem::size_of::<dragonball::api::v1::VmmAction>();
}
