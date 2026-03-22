/// DualKeyCap<P> is !Send — use make_send() for cross-thread transfer.
use capsec::prelude::*;

fn assert_send<T: Send>() {}

fn main() {
    assert_send::<DualKeyCap<FsRead>>();
}
