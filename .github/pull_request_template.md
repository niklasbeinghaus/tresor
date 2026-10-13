## What does this PR do?

<!-- One or two sentences. -->

## Type of change

- [ ] `feat` — new feature
- [ ] `fix` — bug fix
- [ ] `docs` / `chore` / `ci` / `refactor` / `test`

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org) (required — releases are generated from it)
- [ ] `cargo test` passes
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo +nightly fmt --all` applied
- [ ] Golden snapshots reviewed (`cargo insta review`) if views changed
- [ ] New/changed Vault operations go through `VaultApi` + capability gating

## Notes for reviewers

<!-- Anything non-obvious: trade-offs, follow-ups, related issues. -->
