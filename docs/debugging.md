# Debugging

Incident reports land here after production runs (symptom, cause, fix, evidence).

## 2026-09-12 — `dietpi.conf` vs `pi-hole.conf` (ThinkerBoard, DietPi)

- **Symptom:** `./install.sh` stopped at `Phase unbound` with `unbound-checkconf rejected the config`, leaving a broken `pi-hole.conf` on disk next to DietPi's `dietpi.conf`.
- **Cause:** the installer only checked same-path overwrites and validated *after* deploying, so the duplicate root `forward-zone "."` (one per file) was never caught upfront — and `checkconf` stderr was swallowed, hiding the real error.
- **Fix:** sibling scan for root forward-zones (comment-aware, include-aware) with backup + prompt before touching anything; protected names (`dietpi.conf`, `pi-hole.conf`) always ask, even with `--yes`; visible `checkconf` output; auto-revert of the just-deployed file when the full check fails.
