# Design: WS2 foundations — typed Command layer, actor decomposition, durable event journal

*Status: **proposed — awaiting approval before implementation.** Part of
`docs/ROADMAP-ecosystem-importance.md` workstream WS2, entry point "foundations
first" (= `docs/ROADMAP-2.0-and-beyond.md` Phase F1). This is the load-bearing,
highest-risk work: it reshapes the live message path, so it ships as a series of
**behavior-preserving increments**, each gauntlet-green, behind a frozen public
surface — the same discipline that made the WS1.1 extraction safe.*

## Why this first (the hidden shared foundation)

Four of the most-wanted capabilities — MLS groups (need totally-ordered commit
delivery), durable history + multi-device (need a replayable journal), relay
horizontal scaling (needs pluggable durable storage), and dropping the
"resync-as-correctness" hack — are faces of **one** investment: move from "lossy
broadcast + best-effort mailbox + one SQLite mutex + an 8.3k-line shared-mutable
god-object" to "**append-only logs with per-consumer cursors, and one owning actor
per subsystem, behind a typed `Command` layer.**" Build this and the ambitious WS2
crypto (MLS, Double Ratchet) lands on prepared ground instead of forcing a second
rewrite.

## Current state (measured)

- **`crates/huddle-core/src/app/mod.rs` is 8,312 lines.** `AppHandle` (struct at
  `mod.rs:395`) has **20 fields — 14 are `Arc<Mutex<…>>`** guarding in-memory maps
  (`active_rooms`, `sas_flows`, `pending_code_secrets`, discovery/NAT/cooldown
  maps, …), plus `db: Arc<Mutex<Connection>>`, the read-only `identity`, the
  `NetworkHandle`, and `app_event_tx`.
- **~140 public methods** are the surface the TUI (`crates/huddle`) and GUI
  (`crates/huddle-gui`) call. Per the project's load-bearing rule, **this surface
  must not change** — every front-end stays on `AppHandle`.
- **Events** flow through one `tokio::sync::broadcast::Sender<AppEvent>` (capacity
  1024, 41 variants). It is **lossy**: a lagging subscriber drops events, and the
  front-ends paper over it with full re-queries (TUI grace-summary, GUI ~1s poll).
  The code itself flags this (`mod.rs:710`): "resilience, not correctness." Dropped
  **security** prompts (SAS, inbound-dial, safety-number-change) are the real
  hazard.
- **DB** is a synchronous `std::sync::Mutex<Connection>`; the convention "snapshot,
  drop the guard before `.await`" is comment-enforced only.
- **Two long-lived tasks**: the relay reconnection loop (`spawn_server_connection`)
  and the 15 s announcement ticker (`spawn_announcement_ticker`).

## Goal

Decompose `AppHandle` into **one owning actor per subsystem**, each holding its own
state and reachable through a **typed `Command` enum**, and replace the lossy event
broadcast with a **durable, append-only event journal with per-consumer cursors** —
all behind an unchanged `AppHandle` facade so the TUI and GUI compile and behave
identically.

This dissolves the hand-rolled race guards, makes every command rate-limitable and
loggable, removes the resync hack (events are never silently dropped), and is the
seam that later makes mobile FFI and MLS clean.

## Non-goals

- **No public-surface change.** `AppHandle`'s ~140 methods keep their signatures
  and semantics; only the internals move behind actors. Front-ends are untouched.
- **No wire or on-disk format change** in the actor/command increments. (The
  journal increment adds an internal table; the relay-service increment is
  sequenced last and gets its own spec.)
- **Not MLS / Double Ratchet** — those are the WS2 *crypto* tracks that sit on this
  foundation; out of scope here.
- **Not a rewrite.** Each increment moves one subsystem and lands green; the
  god-object shrinks incrementally, never in a big bang.

## Target architecture

```
front-ends (TUI / GUI)  ──calls──▶  AppHandle  (thin facade, frozen surface)
                                       │  translates each call into a typed Command
                                       ▼
                         ┌───────────────────────────────┐
   typed Command enum →  │  per-subsystem actors          │
                         │  SasActor · FileActor ·         │  each owns its state,
                         │  RoomActor · ContactActor ·     │  no shared lock across
                         │  NetworkActor                   │  subsystems
                         └───────────────────────────────┘
                                       │ append events
                                       ▼
                         durable event journal (append-only,
                         per-consumer cursors) ── replaces broadcast::channel
                                       │
                         shared, read-only: identity · db (behind a storage trait) · config
```

A `Command` is `{ inputs } -> Result<Reply, CommandError>` (typed errors replace
the stringly `HuddleError::Session(format!(…))` soup); an actor turns a command
into state mutations + a `Vec<AppEvent>` appended to the journal. The facade
remains synchronous-looking to callers.

## Decomposition into increments (each behavior-preserving, gauntlet-green)

| # | Increment | Spends | Risk | Proves |
|---|---|---|---|---|
| **1** | **`SasActor`** — extract SAS verification behind a typed command/event seam | nothing (pure internal shape) | **low** | the actor/command pattern, on the most isolated subsystem |
| 2 | `FileActor`, then `ContactActor` — next-most-isolated subsystems | nothing | low–med | the pattern generalizes past a trivial case |
| 3 | **Durable event journal** + per-consumer cursors; retire `broadcast` + the resync hack | storage + discipline | med | security prompts are never dropped; multi-device backbone |
| 4 | `RoomActor` / `NetworkActor` (the hot path: `active_rooms`, Megolm, the swarm) | the god-object's core | **high** | the decomposition holds for the live message path |
| 5 | Ordered/durable **relay delivery service** + pluggable storage trait *(separate spec)* | dumb-relay simplicity | high | MLS ordering + relay scaling |

Increments 1–2 are pure refactors. Increment 3 is the correctness win. Increments
4–5 are the heavy lifts and each get their own go/no-go.

## Increment #1 — `SasActor` (the first concrete step)

**Why SAS:** measured as the smallest, least-coupled subsystem — ~350 lines
(~324 purely in-memory), **zero DB access in its handlers**, and **no coupling to
`active_rooms` / Megolm / room crypto**. Ideal to prove the seam with minimal blast
radius. (File transfer is ~435 lines and tightly bound to DB + room crypto on every
chunk — deferred to increment 2.)

**What moves** (all in `crates/huddle-core/src/app/mod.rs` today):
- State: `sas_flows: Arc<Mutex<HashMap<String, SasFlow>>>` (`mod.rs:429`) + the
  `SasFlow` struct (`mod.rs:341–366`).
- Inbound handlers: `SasInit` (`5347–5467`), `SasResponse` (`5468–5553`),
  `SasConfirm` (`5752–5797`).
- Public methods: `sas_start` (`6980`), `sas_match` (`7015`), `sas_cancel`
  (`7068`); the DB-touching `finish_sas` (`7074–7105`) stays at the facade (see
  below).
- Events: `SasCodeReady`, `SasVerified`.

**Shape:**
```rust
// crates/huddle-core/src/app/sas_actor.rs  (new)
pub struct SasActor { flows: Mutex<HashMap<String, SasFlow>> }

pub enum SasCommand {
    Start  { room_id, target_fingerprint },
    Match  { tx_id },
    Cancel { tx_id },
    Inbound(SasInbound),            // Init / Response / Confirm, post-verify_signed
}
pub enum SasOutcome {
    Publish(RoomMessage),           // signed + sent by the facade (actor owns no network)
    Emit(AppEvent),                 // appended to the journal by the facade
    Finalize { room_id, partner_fingerprint, pq_capable },  // facade does the 2 repo writes
}
impl SasActor {
    pub fn handle(&self, cmd: SasCommand, identity: &IdentityKeys, now_ms: i64)
        -> Result<Vec<SasOutcome>, CommandError>;   // pure: state + crypto, no I/O
}
```

The actor is **I/O-free**: it returns `Publish`/`Emit`/`Finalize` *intents*; the
`AppHandle` facade performs signing+network send, journal/event emission, and the
two `repo::set_member_verified` / `repo::add_verified_peer` writes. This keeps the
actor unit-testable without a DB or network and is the template for every later
actor.

**Facade delegation (surface unchanged):**
```rust
impl AppHandle {
    pub async fn sas_start(&self, room_id: &str, target_fp: &str) -> Result<String> {
        let outcomes = self.sas.handle(SasCommand::Start{…}, &self.identity, now_ms())?;
        self.apply_sas_outcomes(outcomes).await   // publish / emit / finalize
    }
}
```

**Tests:** the existing SAS unit/integration coverage MUST stay green unchanged
(behavior-preserving); add direct `SasActor::handle` table tests (the new payoff —
the state machine is now testable in isolation, no `AppHandle` spin-up). Full
gauntlet + fmt + clippy + deny per `CLAUDE.local.md`.

## Invariants (every increment)

- **Frozen public surface** — `AppHandle`'s method signatures + semantics are
  byte-for-byte the contract; front-ends never change. A diff that touches
  `crates/huddle/` or `crates/huddle-gui/` (beyond nothing) is a smell.
- **Behavior-preserving** — same events, same ordering, same DB writes, same wire.
  Proven by the existing gauntlet staying green; new tests are additive.
- **No lock held across `.await`** — actors own their state; the facade composes.
- **Typed errors** — new code uses a `CommandError` taxonomy, not
  `HuddleError::Session(String)`; map at the facade boundary to keep callers stable.

## Risks & mitigations

- **The hot path (increment 4) is genuinely risky** → it is sequenced last, after
  the pattern is proven on SAS/files/contacts and the journal exists; its own
  go/no-go.
- **Event ordering subtly changes when batching outcomes** → the facade emits in
  the actor's returned order; golden event-sequence tests on the SAS flow lock it.
- **Scope creep into MLS / relay changes** → explicitly out of scope; increments
  4–5 gate separately.
- **Turn/complexity budget** → one increment per change-set, each independently
  shippable; the god-object shrinks monotonically.

## Open questions (for approval)

1. **Actor execution model** — pure `handle(cmd) -> Vec<Outcome>` synchronous
   functions composed by the facade (proposed — simplest, most testable, no new
   tasks), vs. true message-passing tasks per actor (more isolation, more
   machinery). Recommend starting pure and introducing tasks only where a subsystem
   genuinely needs to own a loop (NetworkActor).
2. **Journal storage (increment 3)** — a new SQLite append-only table with a
   per-consumer cursor (proposed, reuses the existing DB) vs. a separate store.
3. **Ship cadence** — increment 1 as its own `2.0.5` (internal, no wire change),
   or batch 1–2 before a release? Recommend shipping increment 1 alone to validate
   the pattern end-to-end through a real release.
