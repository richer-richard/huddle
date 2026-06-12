//! huddle 2.0.4 (WS1.1): invite encoding / decoding / signing moved to
//! `huddle-protocol`. Re-exported here at `crate::invite::…` so call sites are
//! unchanged. `sign_invite` now takes `&IdentityKeys`; callers passing
//! `&Identity` reach it by deref coercion (`Identity: Deref<IdentityKeys>`).

pub use huddle_protocol::invite::*;
