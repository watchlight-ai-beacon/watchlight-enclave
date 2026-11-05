## What changed, and why

<!-- The why matters more than the what; a diff shows the what. If this fixes
     something, say what went wrong rather than only what you changed. -->

## Which contract does this touch?

<!-- See CHANGELOG.md. Tick every one that applies — the second is the one
     people miss. -->

- [ ] **CLI surface or `enclave.yaml` schema** — needs a CHANGELOG entry
- [ ] **How strictly `verify` reads a bundle** — needs a CHANGELOG entry under
      **Verifier**, in those words. A stricter verifier breaks a CI gate even
      when the bundle format has not changed: a bundle that exited 0 before may
      exit 1 now
- [ ] **The bundle format** (`wl-enclave-evidence/1`) — does an older verifier
      *misread* a newer bundle? Adding a field is not a bump; changing what a
      field means is
- [ ] None of the above

## Evidence

<!-- Not a checklist of good intentions. CI runs the tests; this is for what CI
     cannot see. -->

- [ ] A test fails without this change. *(For a fix, say so and how you
      checked. A test that passes before and after proves nothing about the bug
      — and a probe aimed at the wrong path looks exactly like a control that
      holds.)*
- [ ] If this adds or changes an attested control: the `verified_by` level is
      justified, and `requested_not_readback` is not standing in for a readback
- [ ] If this touches the guard: recording still precedes forwarding on every
      path, including the ones where a write can fail
- [ ] If this touches a driver: it attests honestly for *its* isolation rather
      than claiming the Docker driver's controls more weakly

## Anything a reviewer should push back on

<!-- Where you are unsure, what you decided not to do, which assumption would
     be expensive if wrong. This section is more useful than a clean one. -->
