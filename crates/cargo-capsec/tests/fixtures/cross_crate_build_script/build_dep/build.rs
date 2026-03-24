fn main() {
    let val = std::env::var("OUT_DIR").unwrap_or_default();
    println!("cargo:rerun-if-changed=build.rs");
    let _ = val;
}
