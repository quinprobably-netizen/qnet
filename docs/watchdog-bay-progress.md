# watchdog-bay: progress ledger

Plan: `docs/watchdog-bay-plan.md`. One fresh Sonnet implementer per task, no
per-task review; one Opus whole-branch review and one fix wave at the end.

| Task | Status | Commit | Notes |
|---|---|---|---|
| T1 backend verbs | done | 62365e5 | gate, patch, label, ack-all, stdin `devices`; 733 cargo + 222 node |
| T2 bay in the state stream | done | dbbd430 | bay.rs, 5 golden fixtures; 791 cargo + 222 node; offline jacks read `:0f` (no address kept) |
| T3 Model.js | done | 6804b4b, 44006af | fixtures on 192.0.2.x; 271 node tests |
| T4 offscreen harness | done | 3a9d5bb | `tools/shot`; 222 node tests. Found: the real card is 488 wide, content 456 (the mockup assumed 488 content) |
| T5a the board | done | 56c4b20 | 283 node tests; shots rest, n30, calm, mode, flip, after-*; card 520 on this view |
| T5b queue, tickets, PIN | done | 309cb71 | 308 node tests; 12 shots; no "recent" section (no per-device log on the Pi) |
| Review | running | | Opus, whole branch d0a119d..HEAD |
| Fix wave | | | |
