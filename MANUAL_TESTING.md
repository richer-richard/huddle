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
- [ ] **First time only:** an onboarding card appears (3 pages) —
      press Enter to advance, "Got it" on the last to dismiss
- [ ] Lobby appears with the `huddle` banner
- [ ] Your fingerprint shows (six groups of four hex chars)
- [ ] "listening on /ip4/.../tcp/..." shows below the fingerprint
- [ ] A NAT-reachability badge appears (likely `🔍 detecting…` on a
      fresh install with no other peers to probe against, then
      transitions to `🏠 LAN only` or `🌐 reachable` once another
      huddle is on the network)
- [ ] On Machine B, run the same — a different fingerprint shows.
      The onboarding card appears once on B too.

## 2. Public room

- [ ] On A, press `s` — modal "start a new room" appears
- [ ] Type a room name (e.g. `lunch-talk`)
- [ ] Encrypted stays at `[ ] no` (default)
- [ ] Press `Enter` — the lobby switches to in-room view; tab `[1]`
      shows the room name
- [ ] On B (still in lobby), within 5-15 seconds the room appears in
      the rooms list (press `r` to refresh if slow)
- [ ] On B, navigate with `j/k` and press `Enter`
- [ ] B's lobby switches to in-room view with the room visible
- [ ] B's member count includes A's fingerprint
- [ ] On A, B's fingerprint now shows in the member list

## 3. Public room messaging

- [ ] On A, press `/` to focus input, type `hello`, press Enter
- [ ] `you  hello` appears in A's chat
- [ ] Within 1-2 seconds, `{A-fingerprint}  hello` appears in B's chat
- [ ] On B, press `/`, type `hi back`, Enter
- [ ] B sees `you  hi back`; A sees `{B-fingerprint}  hi back`

## 4. Encrypted room

- [ ] On A, press `Esc` to blur input, then `^B` to go to lobby
- [ ] Press `s`, name the room `secret`
- [ ] Tab to the encrypted field, Space/Enter to toggle to `[x] yes`
- [ ] Tab to passphrase, type `hunter2`
- [ ] Enter to start — the room opens
- [ ] On B (or back in B's lobby), the room appears with `encrypted`
      label in magenta
- [ ] Enter to join — a passphrase modal appears, title shows 🔒
- [ ] Type `hunter2`, Enter
- [ ] B joins. If wrong passphrase, an error modal shows.

## 5. Encrypted messaging

- [ ] On A, send `secret message` in the secret room
- [ ] B receives `secret message` (Megolm decrypted)
- [ ] On B, send `acknowledged`
- [ ] A receives `acknowledged`

## 6. Phase A — inbound dial accept gate

- [ ] On A, in the lobby, press `d` and enter B's listen multiaddr
      (visible in B's lobby header) with B's peer-id appended, e.g.
      `/ip4/10.0.0.5/tcp/56825/p2p/12D3Koo...`
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

- [ ] On A in an encrypted room, press `^J` — a modal shows an
      `XXXX-XXXX` code valid for 10 minutes
- [ ] OOB-share the code with D (a fourth machine)
- [ ] On D in the lobby, navigate to the room and press Enter to
      open the join modal; press `c` to toggle to code-mode; paste
      the code, Enter
- [ ] D's status line shows "code submitted — waiting for owner
      (up to 30 s)"
- [ ] Within ~3 s D joins; D's room tab shows `(read-only)`
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
- [ ] Both sides see 7 emoji + 3-group decimal code
      (e.g. `🐶 🐱 🦁 🐎 🦄 🐷 🐘   1234-5678-9012`)
- [ ] Compare OOB (call, in-person). Both press `m` to match.
- [ ] Both modals dismiss; A and B now mark each other verified.
      The Verify modal's `[v]` column for that row turns green.

## 11. Phase E — verified-only mode

- [ ] On A press `,` to open Settings; toggle "reject inbound dials
      from unverified fingerprints" to `[x]`
- [ ] From a fresh machine E (not SAS-verified, not trusted), dial A
- [ ] A does NOT raise an InboundDial modal — the dial is silently
      auto-rejected
- [ ] Settings on A now shows the blocked count incremented
- [ ] Press `c` in Settings to clear; E can dial again and get the
      normal Accept/Reject prompt
- [ ] In a room A owns, press `o` — the room toggles its
      `verified_only` flag. Joiners not in A's SAS-verified set get
      a `JoinRefused` reply and an error status.

## 12. Phase C — invite link

- [ ] In a room A owns (or from A's lobby for a peer-only invite),
      press `^I` — a modal shows a `huddle://invite#...` URL plus a
      QR code
- [ ] Copy the URL out of band to B (SMS, AirDrop, paper, whatever)
- [ ] On B in the lobby, press `v` — the paste modal appears
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
- [ ] Launch huddle on both. Lobby badge transitions to `🌐
      reachable` within ~30 s.
- [ ] A starts a room. B sees the room in its lobby (the gossipsub
      mesh now spans the relay).
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

## 16. Multiple rooms / tabs

- [ ] With both rooms open on A, the tab bar shows `[1] room-a [2]
      room-b E*`
- [ ] `^Tab` switches; the `*` clears on the room you view
- [ ] Receive a message in the un-focused room — the `*` reappears

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

- [ ] In any room with two peers, on A press `,` to open Settings,
      then `u` to edit username. Type `alice`, Enter.
- [ ] On A, status line briefly shows "username set to alice"
- [ ] On B, within ~1 s the chat label for A's prior messages
      renders as `alice` instead of the short fingerprint, and an
      in-band status "{abcd}… is now alice" flashes for 4 s
- [ ] On A, send "hi from alice" — both sides see the message with
      sender label `alice`
- [ ] On A, press `,` then `u` again, clear input, Enter — username
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
- [ ] On A, press `,` for Settings, then `!` to open the go-dark
      modal. Try the wrong master passphrase first → inline
      "incorrect master passphrase" appears; passphrase field
      clears.
- [ ] Type the correct master passphrase. `Tab` to the second
      field. Type `DELETE EVERYTHING` (exact case). Enter.
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

- [ ] On A and B (same LAN), launch huddle. Each waits in the lobby
      until mDNS discovers the other — A's HD ID appears in B's
      "known peers" panel.
- [ ] On A press `a`, paste B's HD ID exactly as B sees it in their
      lobby header (`HD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`). Enter.
- [ ] A's status line shows
      "dialing HD-XXXX-… (racing LAN / IP / relay)…".
- [ ] B sees an inbound-dial prompt (or auto-connects if previously
      trusted). The connection uses the LAN ip4 path, not a relay.
- [ ] On A press `a` again, this time type B's username (the one B
      set via Settings → `u`). Enter. Same outcome.
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

## Troubleshooting

- **Peers don't discover** — same-subnet? Some Wi-Fi networks have AP
  isolation. Try a hotspot.
- **Room never appears in lobby** — give it 15-30s for the first
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
