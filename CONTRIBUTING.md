# Contributing

## Conventional commits are required

Every commit message must follow [Conventional Commits](https://www.conventionalcommits.org):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

Why: **releases are generated from commit messages.** The `release-plz` workflow on `main`
computes the next version and the CHANGELOG from them:

| Commit type | Version impact |
|---|---|
| `fix:` | patch (`0.1.0` → `0.1.1`) |
| `feat:` | minor (`0.1.0` → `0.2.0`) |
| `feat!:` / `BREAKING CHANGE:` footer | major (`0.x` → `0.(x+1).0` pre-1.0) |
| `docs:`, `chore:`, `ci:`, `test:`, … | no release |

`ci.yml` lints commit messages and PR titles on every pull request — non-conventional commits fail CI.

## Scope

tresor is a browser, not an admin console. Before proposing a feature, check
[`docs/out-of-scope.md`](docs/out-of-scope.md) — it lists the operations we deliberately
leave to the `vault` / `bao` CLI, with the reasoning. If your idea touches one of those,
explain in your issue or PR how it avoids the "rare / multi-mode / high-blast-radius" trap.

## Workflow

1. Branch: `feat/<short-name>` or `fix/<short-name>`.
2. Write code with tests. The gate is local-equivalent to CI:
   ```bash
   cargo test
   cargo clippy --all-targets -- -D warnings
   cargo +nightly fmt --all -- --check   # nightly: enforces import grouping
   cargo machete
   cargo deny check
   ```
3. Open a PR with a conventional **title**. CI must be green.
4. Squash-merge to `main`.
5. Release automation takes over — see below. You never tag by hand.

## Release process (automated)

```
merge to main ──► release-plz opens/updates a "release" PR (version + CHANGELOG)
merge that PR ──► release-plz creates the tag + GitHub Release
tag push      ──► release.yaml builds all targets and attaches binaries
                  (tarballs/zip + .deb/.rpm/.apk via nfpm)
```

## Code conventions

See `AGENTS.md` for the architecture map and project-specific rules (capability gating,
`Msg`-over-`mpsc`, golden snapshots, strict lints). Golden snapshots are refreshed with
`INSTA_UPDATE=always cargo test --lib ui::<view>` and reviewed via `cargo insta review`.
