# Manual Testing Checklist

This checklist requires two machines connected to the same Wi-Fi network.

## Prerequisites

- Both machines have `huddle-tui` built (`cargo build --release`)
- Both machines are on the same local network (same Wi-Fi / same subnet)
- No firewall blocking mDNS (UDP port 5353) or TCP connections

## Test Steps

### 1. First Launch - Identity Generation

- [ ] Start `huddle-tui` on Machine A
- [ ] Verify: a fingerprint appears in the Status pane (right side)
      Format: `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx` (six groups of four hex chars)
- [ ] Start `huddle-tui` on Machine B
- [ ] Verify: a different fingerprint appears on B
- [ ] Note both fingerprints for comparison

### 2. mDNS Discovery

- [ ] Within 10 seconds, A shows B in the Peers pane (left side)
- [ ] Within 10 seconds, B shows A in the Peers pane
- [ ] Both peers show as online (+ indicator)
- [ ] The fingerprints displayed match what each machine shows in Status

### 3. Session Establishment

- [ ] On Machine A, use Tab to focus Peer List, navigate to B and press Enter
- [ ] Verify: chat pane opens, session is being established
- [ ] Verify: Status pane on A shows "E2EE Active" after a moment
- [ ] Verify: B's peer list shows A with an E indicator (session established)

### 4. Message Exchange

- [ ] On A, type "hello" and press Enter
- [ ] Verify: "hello" appears in A's chat view as "You: hello"
- [ ] Verify: "hello" appears in B's chat view as "Them: hello"
- [ ] On B, press / to focus input, type "hi back", press Enter
- [ ] Verify: B sees "You: hi back"
- [ ] Verify: A sees "Them: hi back"

### 5. Persistence

- [ ] Quit both instances (press q or Ctrl-C)
- [ ] Restart `huddle-tui` on both machines
- [ ] Verify: fingerprints are the same as before (identity persisted)
- [ ] Select the same peer - verify previous messages are loaded from disk
- [ ] Send a new message - verify the session still works without re-handshake

### 6. Network Status

- [ ] Check Status pane on both machines:
  - [ ] Fingerprint shown correctly
  - [ ] Peer count matches (should be 1)
  - [ ] Transport shows "TCP"
  - [ ] Encryption state shows correctly for selected peer
  - [ ] Message count updates as messages are sent/received

## Troubleshooting

- **Peers not discovering:** Check that both machines are on the same
  subnet. Some networks isolate clients (AP isolation). Try
  `ping <other-machine-ip>` first.
- **mDNS blocked:** Corporate networks often block multicast. Try a
  personal hotspot or home network.
- **Firewall:** Ensure UDP 5353 (mDNS) and the dynamic TCP port
  (shown in the log file) are not blocked.
- **Logs:** Check `~/Library/Application Support/huddle/huddle.log`
  (macOS) or `~/.local/share/huddle/huddle.log` (Linux) for errors.
