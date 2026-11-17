# watchdog-bay: progress ledger

Plan: `docs/watchdog-bay-plan.md`. One fresh Sonnet implementer per task, no
per-task review; one Opus whole-branch review and one fix wave at the end.

| Task | Status | Commit | Notes |
|---|---|---|---|
| T1 backend verbs | done | 62365e5 | gate, patch, label, ack-all, stdin `devices`; 733 cargo + 222 node |
| T2 bay in the state stream | running | | |
| T3 Model.js | waiting on T2 | | |
| T4 offscreen harness | done | 3a9d5bb | `tools/shot`; 222 node tests. Found: the real card is 488 wide, content 456 (the mockup assumed 488 content) |
| T5a the board | waiting on T3, T4 | | |
| T5b queue, tickets, PIN | waiting on T5a | | |
| Review | | | |
| Fix wave | | | |
