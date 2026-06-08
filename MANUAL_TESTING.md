# Manual Testing Checklist

Two (or more) machines connected to the same Wi-Fi network for the
basic flows. Scenarios 11–14 (relay / DCUtR / cross-network) need
two machines on **different** networks, and scenario 13 needs a
third machine.

## Prerequisites

- All machines have `huddle` built (`cargo build --release`)
- Same-subnet checks: same Wi-Fi network, mDNS not blocked, dynamic
  TCP ports open
- Cross-network checks: pick a Circuit Relay v2 host (e.g. one of the
  rust-libp2p team's public relays, or run your own) and have its
  multiaddr handy

## 1. First launch

- [ ] On Machine A, run `./target/release/huddle`
- [ ] **First time only:** an onboarding card appears — press Enter
      to advance through the pages, then dismiss the last one
- [ ] The Welcome pane appears with the sidebar on the left
      (`huddle 1.3.1` banner up top)
- [ ] In the sidebar's Profile section, your branded `HD-XXXX-XXXX-…`
      ID is visible. In the default (relay-only) mode the relay dot
      `●` shows next to your name once the onion link is up. With
      `--mode mdns|direct`, a libp2p NAT-reachability badge also shows
      (`detecting` → `private` → `reachable` as AutoNAT probes land)
- [ ] Open the Profile pane (`Enter` on the Profile row, or any j/k
      until it's selected) — listening multiaddrs show under
      "Listen addresses"
- [ ] On Machine B, run the same — a different fingerprint shows.
      The onboarding card appears once on B too.

## 2. Public group room

- [ ] On A, press `g` (or `s`) — modal "start a new room" appears
- [ ] Type a room name (e.g. `lunch-talk`)
- [ ] Encrypted stays at `[ ] no` (default)
- [ ] Press `Enter` — A's pane switches to the Group pane for the new
      room; the sidebar's **Group rooms** section now lists it
- [ ] On B (still on the Welcome / sidebar), within 5-15 seconds the
      room appears under the **Discover** sub-row inside **Group
      rooms** (press `r` to refresh if slow)
- [ ] On B, navigate with `j/k` to the Discover sub-row (or directly
      to the room) and press `Enter`
- [ ] B's pane switches to the Group pane for the room
- [ ] B's member count includes A's fingerprint
- [ ] On A, B's fingerprint now shows in the member list (toggle
      `Alt+M` if the member margin isn't visible)

## 3. Public room messaging

- [ ] On A, press `/` to focus input, type `hello`, press Enter
- [ ] `you  hello` appears in A's chat
- [ ] Within 1-2 seconds, `{A-fingerprint}  hello` appears in B's chat
- [ ] On B, press `/`, type `hi back`, Enter
- [ ] B sees `you  hi back`; A sees `{B-fingerprint}  hi back`

## 4. Encrypted group room

- [ ] On A, press `Esc` to focus the sidebar
- [ ] Press `g`, name the room `secret`
- [ ] Tab to the encrypted field, Space/Enter to toggle to `[x] yes`
- [ ] Tab to passphrase, type `hunter2`
- [ ] Enter to start — A's pane switches to the new Group pane
- [ ] On B, the room appears in the sidebar's Group rooms section
      (under Discover until joined) with an `E` encryption marker
- [ ] Select the room in B's sidebar, press `Enter` to join — a
      passphrase modal appears, title shows `[enc]`
- [ ] Type `hunter2`, Enter
- [ ] B joins. If wrong passphrase, an error modal shows.

## 5. Encrypted messaging

- [ ] On A, send `secret message` in the secret room
- [ ] B receives `secret message` (Megolm decrypted)
- [ ] On B, send `acknowledged`
- [ ] A receives `acknowledged`

## 5b. End-to-end encrypted DM (huddle 0.7.1)

Requires A and B to have shared at least one room previously (so each
has learned the other's Ed25519 pubkey via `MemberAnnounce`). If
they haven't, do scenario 2 first.

- [ ] On A, press `Esc` to focus the sidebar
- [ ] Press `m` — the Compose-DM modal opens
- [ ] Type B's username (or HD-ID); press `Enter`
- [ ] A's pane switches to the DM pane; the sidebar's **Direct
      messages** section now lists B
- [ ] On B, within ~1 s the same DM appears under **Direct messages**
      with the canonical room_id (idempotent on both sides)
- [ ] A sends "hi" — appears in A's DM pane immediately
- [ ] Within ~1-2 s "hi" appears in B's DM pane, decrypted via Megolm
- [ ] Restart A; the DM pane re-bootstraps from disk; reopening the
      DM still decrypts past messages
- [ ] Confirm a third machine C never sees the DM in its sidebar:
      the consumer-side visibility filter drops Direct announces
      addressed to anyone else

## 5c. Add a contact by connect code (huddle 1.2.1)

Both A and B must be connected to the relay (relay dot `●` lit). No prior
shared room is needed — this is a cold first contact over the relay.

- [ ] On A, press `G` — a "your connect code" modal shows an 8-char code
      (e.g. `K7M9-Q2X4`) with a 5-minute countdown; `c` copies it
- [ ] Read/paste the code to B out of band
- [ ] On B, press `a`, type (or paste) the code, press `Enter`
- [ ] Within ~1-2 s A sees a contact request from B (status line +
      Contacts → Requests)
- [ ] A accepts it from the Requests tab; a DM with B opens on both sides
- [ ] A sends "hi"; it reaches B over the relay (and vice versa)
- [ ] Wait >5 min, generate a *new* code on A, and confirm an *old* code
      no longer resolves on B ("invalid or expired connect code")
- [ ] GUI parity: in the desktop app, the add-contact dialog's *Generate a
      code to share* shows the same code, and its input box accepts a code

## 5d. Offline first contact over the relay (huddle 1.2)

- [ ] With B fully closed, on A add B by HD-ID (or have B mint a code
      before closing and redeem it while B is offline)
- [ ] The request is mailboxed by the relay (no error on A)
- [ ] Start B; within a few seconds of connecting, the queued request
      surfaces in B's Contacts → Requests (it is *not* rejected as stale,
      even if minutes/hours passed)
- [ ] B accepts; a DM converges and messages flow both ways

## 5e. About window + GitHub link (GUI, huddle 1.2.1)

- [ ] In the desktop app, open Settings → Account → **About huddle**
- [ ] The window shows the version and a clickable link to
      `github.com/richer-richard/huddle` that opens in the browser

## 6. Phase A — inbound dial accept gate

- [ ] On A, from the sidebar, press `d` and enter B's dial address —
      copy it straight from B's Profile pane: the `dial address N` rows
      are complete multiaddrs that already include B's peer-id, e.g.
      `/ip4/10.0.0.5/tcp/56825/p2p/12D3Koo...` (the bare `peer-id` row
      is shown separately too)
- [ ] On B, an "InboundDial" modal appears with A's short fingerprint
      and the options `[a]ccept` / `[r]eject` / `[t]rust+accept`
- [ ] Press `a` on B — the modal dismisses; A's fingerprint appears
      in B's known peers (no `t`, so not auto-trusted on next dial)
- [ ] Repeat the dial; B should still get a fresh modal (untrusted
      flow re-prompts)
- [ ] On B, press `t` this time — fingerprint sticks as trusted; a
      third dial connects without prompting

## 7. Phase A — inbound dial reject + persistent block

- [ ] Pick a fresh machine pair (or unblock first via Settings, step
      8a)
- [ ] On A, dial B's multiaddr
- [ ] On B, press `r` on the modal — A disconnects
- [ ] Settings on B (`,`) shows "blocked peers: 1"
- [ ] A re-dials — B does NOT raise a second modal; the connection
      is silently dropped (auto-reject path)

## 8. Phase B — kick and rotate (3 machines)

- [ ] On A, start an encrypted room `room-b` with passphrase `first`
- [ ] B joins with `first`, C joins with `first`
- [ ] A sends "pre-kick" — both B and C receive it
- [ ] On A in the room, press `^K` — a member picker appears
- [ ] Select B's row, Enter — modal shows the new passphrase A's
      client generated (write it down)
- [ ] On C, a RotationRequested modal appears — enter the new
      passphrase, Enter
- [ ] A sends "post-kick — C only" — C decrypts; B receives nothing
      visible (the gossipsub bytes arrive but no MessageReceived
      event since B has no matching inbound session)
- [ ] On A (owner), press `B` (Shift+b) — an Info modal lists B's
      fingerprint among the bans for this room

## 9. Phase F — short-lived join code (read-only joiner)

- [ ] On A in an encrypted Group pane, press `Ctrl+J` — a modal shows
      an `XXXX-XXXX` code valid for 10 minutes
- [ ] OOB-share the code with D (a fourth machine)
- [ ] On D in the sidebar, navigate to the encrypted group under
      **Discover** (it must be visible there), then press `c` to
      open the join-with-code modal; paste the code, Enter
- [ ] D's status line shows "code submitted — waiting for owner
      (up to 30 s)"
- [ ] Within ~3 s D joins; the Group pane header shows `(read-only)`
- [ ] A sends a message — D receives + decrypts it
- [ ] D tries to send — works (D can send into the room)
- [ ] If D had used a wrong/expired code: after 30 s an Error modal
      appears: "code join: no response from owner — code may be
      wrong or expired"

## 10. Phase G — SAS verify

- [ ] In any shared room with A and B, on A press `^V` — Verify
      modal shows members
- [ ] Select B's row, press `s` — SAS modal opens, "waiting for
      partner to accept…"
- [ ] On B, a Sas modal appears; B presses Enter / `m` to accept
- [ ] Both sides see the same 7-word + 3-group decimal code
      (e.g. `dog cat lion horse unicorn pig elephant   1234-5678-9012`)
- [ ] Compare OOB (call, in-person). Both press `m` to match.
- [ ] Both modals dismiss; A and B now mark each other verified.
      The Verify modal's `[v]` column for that row turns green.

## 11. Phase E — verified-only mode

- [ ] On A press `,` to jump to the Settings pane (or open the
      Settings modal); press `V` to toggle "reject inbound from
      unverified" to `on`
- [ ] From a fresh machine E (not SAS-verified, not trusted), dial A
- [ ] A does NOT raise an InboundDial modal — the dial is silently
      auto-rejected
- [ ] Settings pane's "blocked peers" count is incremented
- [ ] Press `B` in Settings to open the blocked-peers manager (or use
      the Settings modal's `c`) to clear; E can dial again and get
      the normal Accept/Reject prompt
- [ ] In a Group room A owns, press `Ctrl+O` — the room toggles its
      `verified_only` flag. Joiners not in A's SAS-verified set get
      a `JoinRefused` reply and an error status.

## 12. Phase C — invite link

- [ ] In a Group pane A owns (or from any non-chat pane for a
      peer-only invite), press `Shift+I` — a modal shows a
      `huddle://invite#...` URL plus a QR code
- [ ] Copy the URL out of band to B (SMS, AirDrop, paper, whatever)
- [ ] On B from the sidebar, press `v` — the paste modal appears
- [ ] Paste the URL, Enter — a confirmation modal shows the claimed
      fingerprint
- [ ] Press `d` to dial — B's TUI says "dialing … via invite". When
      libp2p completes Identify, the post-dial fingerprint check
      runs; mismatch ⇒ "invite fingerprint mismatch — connection
      dropped" Error modal.
- [ ] If the invite included an encrypted room, B is prompted for the
      passphrase next.

## 13. Phase C — invite tamper (security drill)

- [ ] On A, generate an invite as in step 12
- [ ] Copy the URL into a text editor, base64-decode the fragment
      (everything after `#`), edit the `fingerprint` field to a
      different value, base64-encode and replace
- [ ] Paste the tampered URL into B; B's confirmation modal shows
      the FORGED fingerprint
- [ ] B confirms; the dial succeeds and Identify lands. The post-dial
      check fires: "invite fingerprint mismatch — claimed: ABCD…
      actual: 745e… the invite link may be forged" — connection
      dropped.

## 14. Phase D — internet reach via Circuit Relay v2

- [ ] On both A and B, pick a relay multiaddr (the rust-libp2p team
      publishes some; or self-host one).
- [ ] Add to each machine's `config.toml`:
      ```toml
      relays = ["/dns4/relay.example.com/tcp/4001/p2p/12D3..."]
      ```
- [ ] Connect A and B to **different** networks (one home, one
      cellular hotspot is enough).
- [ ] Launch huddle on both. The Profile pane / sidebar NAT badge
      transitions to `reachable` within ~30 s.
- [ ] A starts a group room. B sees the room in the sidebar's
      Discover row (the gossipsub mesh now spans the relay).
- [ ] B joins. Messages flow.
- [ ] After a few minutes, DCUtR may upgrade the connection to direct
      — status line briefly shows "direct connection to …<peer>".

## 15. Phase D — host_addrs auto-bootstrap

- [ ] Same setup as scenario 14, but B never received an invite link
      from A — B just sees A's room announcement on the global topic
- [ ] B's TUI logs "opportunistic dial via room announcement
      host_addrs" (visible at `--log-level debug`) and dials A's
      circuit address from the announcement
- [ ] The mesh forms; B joins and messages flow as in scenario 14

## 16. Multiple rooms (sidebar navigation)

- [ ] On A, join two rooms (`room-a` public, `room-b E` encrypted)
- [ ] Both appear under **Group rooms** in the sidebar with their
      member counts (and `E` marker on the encrypted one)
- [ ] On A while in the `room-a` pane, have C send a message in
      `room-b` — the sidebar row for `room-b` shows an unread
      `(1)` badge
- [ ] Press `Esc` to focus the sidebar, `j`/`k` to move to `room-b`,
      `Enter` to switch — the `(1)` clears on activation
- [ ] `R` (Shift+R) from the sidebar marks every room read at once

## 17. Leaving

- [ ] On B in a room, `^L` leaves that room
- [ ] On A, B's fingerprint disappears from the members list within
      a couple seconds (MemberLeave broadcast)

## 18. Persistence

- [ ] Quit both with `q` then `y`
- [ ] Restart both
- [ ] Fingerprints match what they were before
- [ ] Onboarding card does NOT appear again
- [ ] Persistent rooms re-discover automatically once another peer
      re-announces them
- [ ] Past messages can be re-read after rejoining

## 19. Host disappears

- [ ] Create a room on A, have B join
- [ ] Quit A entirely
- [ ] On B, the room continues to function. Send a message — saved
      locally even if no one else is online
- [ ] If a third machine C joins the room later (while B is still
      announcing), C connects to B and gets the session key

## 20. Username & verified ✓ in chat (huddle 0.5)

- [ ] In any room with two peers, on A press `,` to jump to the
      Settings pane (or open the Settings modal), then `E` to edit
      username. Type `alice`, Enter.
- [ ] On A, status line briefly shows "username set to alice"
- [ ] On B, within ~1 s the chat label for A's prior messages
      renders as `alice` instead of the short fingerprint, and an
      in-band status "{abcd}… is now alice" flashes for 4 s
- [ ] On A, send "hi from alice" — both sides see the message with
      sender label `alice`
- [ ] On A, press `,` then `E` again, clear input, Enter — username
      reverts to `[anonymous]`. On B, A's messages now render as
      `[anonymous]`.
- [ ] If A and B have completed SAS verification (scenario 10), each
      side sees a green `✓` after the sender name on every chat line
      from the verified counterpart. Suppressed for one's own
      outbound messages.

## 21. Go dark — account deletion (huddle 0.5)

**Use a throwaway data dir for this.** Set a non-default `HOME` or
move `~/Library/Application Support/huddle` (macOS) / `~/.local/share/huddle`
(Linux) aside before starting.

- [ ] Start huddle, set a master passphrase at first launch, join
      one or two rooms with another peer.
- [ ] On peer B, confirm A's fingerprint is in the member list.
- [ ] On A, open the go-dark modal with the deliberately-awkward
      `Alt+Shift+1` chord (macOS: Option+Shift+1; the bare `!` was
      removed in 0.7.4 as too easy to fat-finger). It fires from any
      non-typing context and is also reachable from the command palette
      (`Ctrl+P` / `:`) as "go dark (delete account)". Try the wrong
      master passphrase first → inline "incorrect master passphrase"
      appears; passphrase field clears.
- [ ] Type the correct master passphrase and press Enter. (The modal has a
      single field — in a `--no-master-passphrase` session there is no
      passphrase to check, so you type the literal phrase `DELETE EVERYTHING`,
      exact case, instead.)
- [ ] On B, within ~2 s A leaves every shared room. A's
      `MemberLeave` arrives; the member list updates.
- [ ] On A, a "Goodbye. huddle has gone dark." modal shows for
      ~2 s, then the process exits.
- [ ] Inspect the data dir — `huddle.db`, `huddle.db-shm`,
      `huddle.db-wal`, `keychain.salt`, `huddle.log`, and
      `config.toml` are all gone. The dir itself is removed if it
      was empty.
- [ ] Relaunch huddle on A. Onboarding card reappears, a fresh
      fingerprint is generated, no memory of previous rooms /
      peers / messages.

## 22. Add friend by HD ID or username (huddle 0.5.1+, racing in 0.5.2+)

- [ ] On A and B (same LAN), launch huddle. Each waits until mDNS
      discovers the other — A's HD ID appears under the **People**
      section of B's sidebar.
- [ ] On A press `a`, paste B's HD ID exactly as B sees it in their
      Profile pane (`HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`). Enter.
- [ ] A's status line shows
      "dialing HD-XXXX-… (racing LAN / IP / relay)…".
- [ ] B sees an inbound-dial prompt (or auto-connects if previously
      trusted). The connection uses the LAN ip4 path, not a relay.
- [ ] On A press `a` again, this time type B's username (the one B
      set via Settings → `E`). Enter. Same outcome.
- [ ] Try a random HD ID neither of you has seen
      (`HD-0000-0000-0000-0000-0000-0000`): the modal closes and
      an Error appears: "haven't seen `HD-0000…` on the network
      yet — ask them for an invite link". This is the privacy-
      preserving floor: no central directory.
- [ ] Cross-network drill: A and B on different networks, both with
      a working relay in `config.toml`. A's `host_addrs` will
      include both a public-ish ip4 + a `/p2p-circuit` address.
      Repeat the add-friend by HD ID on the other side; libp2p
      races them, the relay path typically wins (direct IP from
      NATs usually fails), DCUtR may later upgrade to direct.
- [ ] Username collisions: have two peers both set the same
      username and announce. On the third peer, typing that
      username into add-friend should produce
      "username `X` is ambiguous (2 peers share it) — use their
      HD- ID instead".

## 23. huddle 1.0 — LAN + relay both on by default

- [ ] Launch with NO flags. The Welcome pane shows a status line with
      both `LAN ● on` and `relay ● <door>` (once Tor connects). The
      sidebar's bottom-left shows the relay door; the Profile row shows a
      NAT badge too (libp2p is running).
- [ ] Stop Tor (`systemctl stop tor`), relaunch. `relay ○ connecting…`
      but two machines on the same Wi-Fi still discover each other and
      chat over LAN — the app is useful with no Tor at all.

## 24. huddle 1.0 — add a contact by HD-ID over the internet

- [ ] A and B on **different** networks (no shared LAN), both on the
      default relay. On A press `a`, paste B's full `HD-…` ID, Enter.
      Status: "contact request sent to HD-… — opens a DM when they accept".
- [ ] On B (even if B was offline and just launched), open the Contacts
      pane (`p`). The **Contact requests** tab shows A. Press `a` to accept.
- [ ] A DM opens on both sides; messages flow over the relay. Confirm the
      DM header shows `via relay`.
- [ ] Decline path: repeat, press `r` on B — the request disappears and no
      DM opens.

## 25. huddle 1.0 — DM persists across restart

- [ ] With the DM from scenario 24 established, quit A (`q`, `y`) and
      relaunch. The DM is still in the sidebar's Direct messages section
      without reopening it.
- [ ] From B, send a message. A receives it immediately on the restarted
      client (pre-1.0 this was silently dropped until manual reopen).

## 26. huddle 1.0 — transport doors + clearnet relay

- [ ] `huddle transports` prints all five doors with AVAILABLE/unavailable
      + each one's privacy tradeoff, in the order they'd be tried.
- [ ] Self-host a clearnet relay: on the VPS, `HUDDLE_SERVER_BIND=0.0.0.0:8787
      huddle-server` and open the port. On a client:
      `huddle --clearnet-server ws://<vps-ip>:8787/ws --transport clearnet-ws`.
      Settings → Network shows `Relay ● connected · Clearnet plain (ws)`,
      and chat works without Tor.
- [ ] Pin/fallback: `--transport onion-tor` forces the onion door; with Tor
      down and a clearnet URL set, the default order falls through to the
      clearnet door automatically (watch `huddle.log`).

## 27. huddle 1.0 — per-chat transport indicator

- [ ] Open a DM with a peer on the same LAN — the header shows `via lan`.
- [ ] Move that peer off the LAN (different network) while keeping the relay
      up — the same DM's header flips to `via relay`, and chat keeps working.
- [ ] With neither a direct connection nor the relay, the header shows
      `offline` (messages still save locally).

## 28. huddle 1.1.4 — enforced relay auth + live Dark/Light theme

- [ ] **Relay client auth (old client rejected).** Run the 1.1.4
      `huddle-server`. Connect a *pre-1.1.4* `huddle` build (one without the
      challenge-response handshake): its relay door never reaches
      `● connected` (Settings → Network shows it connecting/failed), and the
      server log records a rejected handshake. A 1.1.4 client connects
      normally and chat over the relay works — confirming the relay now
      requires every client to prove its fingerprint via an Ed25519
      signature over the challenge nonce.
- [ ] **Theme toggle (live).** Go to Settings → Appearance. The active theme
      (`Dark` by default) is highlighted; press `T`. The whole TUI repaints
      instantly in the high-contrast Light palette — no restart — and the
      status line shows `theme: Light`. Press `T` again to return to Dark.
      Accents, sidebar, chat, and hint chips all re-skin together.
- [ ] **Theme persists.** Quit and relaunch huddle — it comes back up in the
      last-chosen theme (stored in the shared `theme` setting; the desktop
      GUI honors the same value).
- [ ] **Update check over Tor.** With the update check opted in (Settings →
      Privacy) and Tor reachable, the daily crates.io poll succeeds through
      the SOCKS proxy; with Tor down it silently skips rather than making a
      direct clearnet request (no IP leak).

## 29. huddle 1.2.4 — attach a file by typing a path

- [ ] **TUI, file picker → path entry.** In a room, open the file picker
      (`Ctrl+A`), then press `p`. The "attach a file by path" modal appears.
      Type `~/some-file.txt` and Enter — confirm `~` expanded to `$HOME` and
      the file is offered (a file card appears in chat).
- [ ] **TUI, bad path is non-destructive.** Open the path modal again, type a
      path that doesn't exist, Enter. An inline `! …` error shows and the text
      you typed is **kept** (not cleared). Fix the path, Enter — it sends.
- [ ] **TUI, palette.** Confirm "attach a file by path" is also reachable from
      the command palette (`Ctrl+P` / `:`).
- [ ] **GUI, toggle defaults off.** In the desktop app, Settings → Privacy —
      "attach by typing a path" starts **unchecked**. Click Attach in a chat:
      the native OS file dialog opens.
- [ ] **GUI, toggle on.** Enable the toggle, click Attach: a path-entry box
      opens instead of the native dialog. Type an absolute path and press
      Enter (or click Attach) to send it.
- [ ] **GUI, persists.** Quit and relaunch the GUI — the toggle is still on.

## 30. huddle 1.3.0 — post-quantum hybrid DM encryption

- [ ] **Two 1.3 peers → hybrid DM works.** With both A and B on 1.3.0, start a
      DM (A → B's `HD-…` ID), exchange a few messages each way. Messages send
      and decrypt normally. There is **no visible change** — the post-quantum
      hybrid key agreement is transparent; this confirms it didn't break DMs.
- [ ] **Restart survives.** Quit and relaunch both. Reopen the DM, send a
      message — it still works (the DM re-derives its hybrid key once the
      partner re-announces; persisted history still decrypts).
- [ ] **Backward compatible with a pre-1.3 peer.** Have one side run an older
      build (≤1.2.5) and the other on 1.3.0, start a DM. It still works — the
      1.3 side automatically falls back to the classical X25519 DM key. (A DM
      goes hybrid only when *both* peers are 1.3+.)
- [ ] **Logs (optional).** With `RUST_LOG=huddle=debug`, a DM between two 1.3
      peers shows no `DM hybrid … failed` / `DM classical derivation failed`
      warnings — derivation succeeds silently. A warning here would indicate a
      malformed announce or a key-agreement failure.
- [ ] **Group rooms unchanged.** Create/join an encrypted *group* room and send
      messages — group behaviour and wire format are unchanged by 1.3.

## 31. huddle 1.3.1 — post-quantum downgrade hardening + handshake liveness

- [ ] **Pin survives restart (no downgrade).** With A and B both on 1.3.1, run a
      hybrid DM, then quit and relaunch both. Reopen the DM and send a message —
      it still works, derived hybrid (the ML-KEM pin persisted in the DB, so the
      DM does not silently fall back to classical).
- [ ] **Rollout upgrade heals without restart.** Start a DM with one side on
      ≤1.3.0 (or pre-1.3) so it keys classical; then upgrade that side to 1.3.1
      while the chat is open. Within ~15s the DM converges to hybrid and keeps
      working — no manual restart. (With `RUST_LOG=huddle=info` the upgrading
      side logs `DM upgraded classical→hybrid (post-quantum)`.)
- [ ] **Stalled handshake self-heals.** On a flaky link, a freshly-opened hybrid
      DM still establishes within a couple of announce intervals (the responder
      asks for the KEM ciphertext and a bounded retry re-prompts) rather than
      hanging until a restart.
- [ ] **Pre-1.3 peer still works (not bricked).** A 1.3.1 ↔ pre-1.3 DM still
      completes over the classical fallback (a peer that never advertises ML-KEM
      is treated as genuinely non-PQ).
- [ ] **Logs (optional).** `RUST_LOG=huddle=debug` shows no `DM hybrid … failed`
      warnings for a healthy hybrid DM; an unexpected `outbound rotate failed`
      would point at a storage problem during an upgrade.

## Troubleshooting

- **Peers don't discover** — same-subnet? Some Wi-Fi networks have AP
  isolation. Try a hotspot.
- **Room never appears in sidebar** — give it 15-30s for the first
  announcement to propagate through the mesh. `r` to refresh.
- **Wrong passphrase on encrypted join** — error modal shows; any key
  to dismiss.
- **Code-join hangs** — wait the full 30 s; if the code was bad you'll
  see the timeout Error modal. Re-confirm the code with the owner.
- **Relay reservation fails** — confirm the relay multiaddr is alive
  by dialing it from another libp2p client. Some relays require
  authentication.
- **Logs** — `~/Library/Application Support/huddle/huddle.log` on
  macOS, `~/.local/share/huddle/huddle.log` on Linux. Set
  `RUST_LOG=huddle=debug` to see AutoNAT / DCUtR events.
