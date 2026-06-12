# Design: hot-path decomposition — RoomActor / NetworkActor (WS2 foundations #4)

*Status: **designed; the interconnected core is sequenced as a dedicated
project.** Part of `docs/superpowers/specs/2026-06-12-foundations-actor-refactor-design.md`
(the foundations program). This records the evidence-based finding from
extracting the first actors and the plan for the remaining hot-path
decomposition — which, unlike the clean SAS extraction, requires the holistic
actor model rather than piecemeal moves.*

## What the increments so far established

- **SasActor (#1, shipped 2.0.5) was the clean win** because its state
  (`sas_flows`) is *contained*: ~6 call sites, zero coupling to `active_rooms` /
  Megolm / DB on its handlers. It extracted cleanly into an I/O-free actor.
- **Measuring the remaining hot-path state shows the opposite.** `discovered_rooms`
  is read/written at **~14 sites** across dial resolution, room joining, announce
  ingestion, and queries (`app/mod.rs:962, 1731, 1774, 2743, 2899, 3798, 3954,
  3999, 4017, 6624, …`). `active_rooms` is the literal core — every send, receive,
  membership change, Megolm operation, and rotation touches it, under the same
  lock, often interleaved with the `db` lock and the `NetworkHandle`.

The conclusion is not "do more piecemeal extractions." It is: **the hot path is
one interconnected subsystem**, and decomposing it means changing the
*concurrency model*, not relocating a map.

## Why the foundations had to come first (and now have)

A `RoomActor` / `NetworkActor` decomposition that's *behavior-preserving* needs:

1. **A durable event journal** so an actor can emit events without the lossy
   broadcast dropping them mid-handoff — **shipped (#3, 2.0.7)**: `event_journal`
   + the per-`id` cursor API.
2. **An ordered delivery point** so a room actor processes messages in a single,
   total order (no two-lock interleaving) — the relay half **shipped (#5, 2.0.8)**:
   per-room `seq`.
3. **A storage seam** so DB access is a message to an owning task, not a lock
   grabbed from anywhere.

With #3 and #5 in place, the remaining work is the actor model itself.

## The plan (the dedicated project)

```
AppHandle (facade, frozen surface)
  └── Command enum ──▶ RoomActor (one task per room)
                         owns: active_rooms[room], its RoomCrypto, members,
                               typing, issued_codes, the per-room seq cursor
                         loop: select! over { commands, inbound (ordered by seq),
                               timers } — NO shared lock; everything is a message
       ──▶ NetworkActor (owns the swarm + relay client; discovered_rooms,
                          NAT/reachability/dial state; emits NetworkEvents)
       ──▶ shared read-only: identity; db behind a StorageActor/trait; the journal
```

- **One owning task per room** turns `active_rooms`'s shared `Mutex<HashMap>` into
  per-room mailboxes; the hand-rolled race guards (`ensure_dm_key`) dissolve.
- **Inbound messages are fed in `seq` order** (the #5 primitive), giving the total
  order MLS commits require — the same seam MLS (WS2-b) consumes.
- **The facade stays byte-identical**: the ~140 public methods become typed
  `Command`s posted to actors; the TUI/GUI never change.

## Why it is sequenced, not rushed here

This is the **single largest internal change** in the program — it reshapes the
live message path of an 8.3k-line core. Done piecemeal or hastily it risks the
behavior-preservation guarantee every release so far has held. It is its own
multi-PR project (extract `RoomActor` first behind the facade, soak it, then
`NetworkActor`, then the `StorageActor`/trait), each step gauntlet-green, and it
is now *unblocked* by the journal + ordered-delivery foundations shipped in this
program. The cleanly-isolated pieces (SAS) are already extracted; the
interconnected core gets the dedicated treatment it needs.

## Done-criteria for this increment

- The decomposition is designed against the measured reality of the code. ✓
- Its prerequisites (durable journal, ordered delivery) are **shipped**, so the
  project is unblocked. ✓
- The first actor (`RoomActor`) and the storage seam are the next concrete steps,
  to be done as a focused project rather than at the tail of a foundations sweep.
