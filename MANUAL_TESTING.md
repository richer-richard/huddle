# Manual Testing Checklist

Two (or more) machines connected to the same Wi-Fi network.

## Prerequisites

- Both machines have `huddle-tui` built (`cargo build --release`)
- Both machines on the same local network (same subnet, mDNS not blocked)
- UDP 5353 (mDNS) and dynamic TCP ports not firewalled

## 1. First launch

- [ ] On Machine A, run `./target/release/huddle-tui`
- [ ] Lobby appears with the `huddle` banner
- [ ] Your fingerprint shows (six groups of four hex chars)
- [ ] "listening on /ip4/.../tcp/..." appears below the fingerprint
- [ ] On Machine B, run the same — a different fingerprint shows

## 2. Public room

- [ ] On A, press `s` — modal "start a new room" appears
- [ ] Type a room name (e.g. `lunch-talk`)
- [ ] Encrypted stays at `[ ] no` (default)
- [ ] Press `Enter` — the lobby switches to in-room view, room appears
      as tab `[1]`
- [ ] On B (still in lobby), within 5-15 seconds the room appears in
      the rooms list (you might need to press `r` to refresh)
- [ ] On B, navigate to the room with `j` and press `Enter`
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
- [ ] Press `Tab` to focus the encrypted field, press Space or Enter
      to toggle to `[x] yes`
- [ ] Press `Tab` to focus passphrase, type `hunter2`
- [ ] Press Enter to start — the room opens
- [ ] On B (or back in B's lobby), the room appears with `encrypted`
      label in magenta
- [ ] Press Enter to join — a passphrase modal appears
- [ ] Type `hunter2`, press Enter
- [ ] B joins successfully. If wrong passphrase, an error modal shows.

## 5. Encrypted messaging

- [ ] On A, send `secret message` in the secret room
- [ ] B receives `secret message` in plaintext (after Megolm decrypt)
- [ ] On B, send `acknowledged`
- [ ] A receives `acknowledged`

## 6. Multiple rooms

- [ ] With both rooms open on A, the tab bar shows `[1] lunch-talk
      [2] secret E*`
- [ ] Press `^Tab` — switches to room 2 (the `*` clears since you've
      viewed it)
- [ ] Press `1` to jump back to room 1
- [ ] Receive a message in room 2 while viewing room 1 — the `*`
      reappears on tab 2

## 7. Leaving

- [ ] On B in a room, press `^L` — leaves that room, drops back to
      lobby if it was the only tab
- [ ] On A, B's fingerprint disappears from the members list within
      a couple of seconds (MemberLeave broadcast)

## 8. Persistence

- [ ] Quit both with `q` then `y`
- [ ] Restart both
- [ ] Fingerprints match what they were before
- [ ] Persistent rooms (the ones you previously joined) re-discover
      automatically when other peers re-announce them
- [ ] Past messages can be re-read after rejoining

## 9. Host disappears

- [ ] Create a room on A, have B join
- [ ] Quit A entirely
- [ ] On B, the room continues to function. Send a message — saved
      locally even if no one else is online
- [ ] If a third machine C joins the room later (while B is still
      announcing), C connects to B and gets the session key

## Troubleshooting

- **Peers don't discover** — same-subnet? Some Wi-Fi networks have AP
  isolation. Try a hotspot.
- **Room never appears in lobby** — give it 15-30s for the first
  announcement to propagate through the mesh. Use `r` to refresh.
- **Wrong passphrase on encrypted join** — error modal shows; press
  any key to dismiss and try again.
- **Logs** — check `~/Library/Application Support/huddle/huddle.log`
  on macOS or `~/.local/share/huddle/huddle.log` on Linux.
