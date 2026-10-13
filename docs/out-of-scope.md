# Deliberately out of scope (and why)

tresor is a **browser**, not an admin console. This file tracks the negative space: the
Vault operations it deliberately does not implement. It exists so contributors know what
not to build and reviewers have something concrete to point at. It is not a wishlist, and
not a promise that these are impossible forever, just the current considered decision.

Most of these are better served by the `vault` / `bao` CLI or a dedicated tool.

## The principle

> If an operation is **(a) rare**, **(b) multi-mode**, or **(c) high-blast-radius**, prefer:
> **display the state in-TUI, hand the mutation to the CLI or `$EDITOR`.**

The job is to make the common case fast and safe: find a secret, read it, reveal it, copy
it, fix a value. Anything that turns into a form, a state machine, or a footgun belongs in
a purpose-built tool instead.

## Not planned

### PKI issuance / CA management
Generating certificates means multi-field forms, key/cert/bundle formats, CSR handling, role
configuration, and TTL juggling. That is a mode-heavy workflow, brittle in a fixed-width TUI,
and already solved by `vault write pki/issue/...`. A terminal form here would be a worse
version of the CLI it wraps.

### Dynamic secret lease management (DB / AWS / GCP / ...)
Generating a credential is one call, but the value only exists inside a **lease**: renewal,
revocation, and per-lease TTL state. Showing the secret without the lease lifecycle teaches
users to treat a dynamic secret like a static KV one. Half-supporting leases is worse than
not supporting them at all. A read-only lease *browser* is a separate conversation, adjacent
to the KV2 version-history work in #1.

### Policy / auth / audit **configuration**
High blast radius, touched once a year, and exactly the kind of change that should be
reviewed, diffed, and applied deliberately. **Browsing** these is in scope and useful (see
#6); **mutating** them belongs in the CLI or behind an `$EDITOR` handoff, where the result
is a reviewable file.

### Mounting secret engines
Mounting an engine is admin configuration: it changes the server's surface area for every
client, not just the current session. Same blast-radius argument as policy configuration,
so it stays in the CLI.

### HA / raft / rekey / seal / unseal
Shard handling, quorum-sensitive, rare, and audited. Getting unseal wrong in a TUI that
renders to a terminal scrollback is a security problem, not a UX one.

### Recursive / bulk destructive operations
A bulk delete or move is one keystroke away from disaster with no undo. The safe primitive
is **single-secret delete**, which is already implemented with a confirmation prompt and
capability gating. If bulk destructive operations are ever added, they must require **typed
path confirmation**, never a plain y/n.

### Full-screen in-TUI YAML / JSON editors
A ratatui prompt will never out-edit `$EDITOR`, and re-implementing one is a rabbit hole:
syntax highlighting, multi-line paste, encodings, validation. Hand complex or multiline
values off to `$EDITOR` instead (#7) so the user keeps their real editor, their keybindings,
and their plugins.

### Secret sync (backup / restore)
Moving secrets between Vault instances is a job for a dedicated tool with its own
identity, offset, and conflict semantics. It sits in the Go original's `Todo` list as
`secret sync (remote to local)` and is out of scope for a browser.

## Adjacent work that *is* in scope

These come up alongside the items above and are tracked separately:

- **KV2 version history** — view / restore / undelete / destroy versions (#1).
- **Policy browsing** (read-only) with `$EDITOR` handoff for changes (#6).
- **`$EDITOR` handoff** for complex or multiline values (#7).

## The Go original's TODO, revisited

The Go `vaultview` shipped with a small `Todo` list. For reference, where each item stands
in tresor:

| Go TODO | Status |
|---|---|
| `add new secret` | **Shipped** — `n` creates a KV2 secret (capability-gated). |
| `enable new secret engine` | Out of scope — mounting is admin config (see above). |
| `all feature above for policies (+token creations)` | Split: browsing policies is in scope (#6); policy and token *creation* is auth configuration, out of scope. |
| `secret sync (remote to local)` | Out of scope — a different tool (see above). |

## Changing this list

If one of these has a genuinely better in-TUI answer, open an issue that argues the case
against the principle above. In particular, explain how it avoids becoming a form, a state
machine, or a footgun. Absent that, treat this file as the default: **display the state
in-TUI, mutate in the CLI or `$EDITOR`.**
