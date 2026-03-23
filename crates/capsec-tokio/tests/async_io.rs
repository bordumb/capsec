//! Runtime tests for capsec-tokio async wrappers.

use capsec_core::root::test_root;

// ── fs tests ────────────────────────────────────────────────────

#[tokio::test]
async fn async_read_dev_null() {
    let root = test_root();
    let cap = root.fs_read();
    let data = capsec_tokio::fs::read("/dev/null", &cap).await.unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn async_read_to_string() {
    let root = test_root();
    let cap = root.fs_read();
    let data = capsec_tokio::fs::read_to_string("/dev/null", &cap)
        .await
        .unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn async_write_and_remove() {
    let root = test_root();
    let write_cap = root.fs_write();
    let path = std::env::temp_dir().join("capsec-tokio-test-write");
    capsec_tokio::fs::write(&path, b"hello", &write_cap)
        .await
        .unwrap();
    capsec_tokio::fs::remove_file(&path, &write_cap)
        .await
        .unwrap();
}

#[tokio::test]
async fn async_metadata() {
    let root = test_root();
    let cap = root.fs_read();
    let meta = capsec_tokio::fs::metadata("/dev/null", &cap).await.unwrap();
    assert!(!meta.is_dir());
}

#[tokio::test]
async fn async_open_returns_async_read_file() {
    use tokio::io::AsyncReadExt;

    let root = test_root();
    let cap = root.fs_read();
    let mut file = capsec_tokio::fs::open("/dev/null", &cap).await.unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await.unwrap();
    assert!(buf.is_empty());
}

#[tokio::test]
async fn async_create_returns_async_write_file() {
    use tokio::io::AsyncWriteExt;

    let root = test_root();
    let cap = root.fs_write();
    let path = std::env::temp_dir().join("capsec-tokio-test-create");
    let mut file = capsec_tokio::fs::create(&path, &cap).await.unwrap();
    file.write_all(b"test").await.unwrap();
    file.flush().await.unwrap();
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn async_read_dir() {
    let root = test_root();
    let cap = root.fs_read();
    let mut dir = capsec_tokio::fs::read_dir("/tmp", &cap).await.unwrap();
    // Just verify we can iterate
    let _entry = dir.next_entry().await.unwrap();
}

#[tokio::test]
async fn async_copy() {
    let root = test_root();
    let read_cap = root.fs_read();
    let write_cap = root.fs_write();

    let src = std::env::temp_dir().join("capsec-tokio-test-copy-src");
    let dst = std::env::temp_dir().join("capsec-tokio-test-copy-dst");
    std::fs::write(&src, b"copy me").unwrap();

    let bytes = capsec_tokio::fs::copy(&src, &dst, &read_cap, &write_cap)
        .await
        .unwrap();
    assert_eq!(bytes, 7);

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

// ── process tests ───────────────────────────────────────────────

#[tokio::test]
async fn async_run_echo() {
    let root = test_root();
    let cap = root.spawn();
    let output = capsec_tokio::process::run("echo", &["hello"], &cap)
        .await
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
}

#[tokio::test]
async fn async_command_returns_tokio_command() {
    let root = test_root();
    let cap = root.spawn();
    let mut cmd = capsec_tokio::process::command("echo", &cap).unwrap();
    let output = cmd.arg("test").output().await.unwrap();
    assert!(output.status.success());
}

// ── Send assertion ──────────────────────────────────────────────

#[tokio::test]
async fn async_fs_read_future_is_send_with_sendcap() {
    fn assert_send<T: Send>(_: &T) {}
    let root = test_root();
    // SendCap is Send+Sync, so &SendCap across .await keeps the future Send
    let cap = root.fs_read().make_send();
    let fut = capsec_tokio::fs::read("/dev/null", &cap);
    assert_send(&fut);
}

// ── context struct works with async wrappers ────────────────────

#[capsec_macro::context]
struct AsyncTestCtx {
    fs: FsRead,
}

#[tokio::test]
async fn context_struct_works_with_async_wrappers() {
    let root = test_root();
    let ctx = AsyncTestCtx::new(&root);
    let data = capsec_tokio::fs::read("/dev/null", &ctx).await.unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn spawn_with_single_cap() {
    let root = test_root();
    let cap = root.fs_read();
    let handle = capsec_tokio::task::spawn_with(cap, |cap| async move {
        capsec_tokio::fs::read("/dev/null", &cap).await.unwrap()
    });
    let data = handle.await.unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn spawn_with_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let root = test_root();
    let cap = root.fs_read();
    let handle = capsec_tokio::task::spawn_with(cap, |cap| async move {
        capsec_tokio::fs::read("/dev/null", &cap).await.unwrap()
    });
    assert_send(&handle);
    let _ = handle.await.unwrap();
}
