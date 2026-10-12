# Veil server agent workflow

This public MIT repository contains server source, deployment and public protocol
only. Never copy signing keys, deployment secrets or unrelated desktop implementation here.
Read README.md, SECURITY.md and protocol.md before changing networking.

Inspect git status, current branch and existing PR. Preserve uncommitted work.
For ordinary tasks fetch origin and create feature/<task> from origin/develop;
every task uses a separate worktree, even when the checkout is clean. Use Conventional
Commit titles and open PRs into develop. Do not push directly to protected branches,
force-push, bypass checks or merge without task authorization. main is reviewed
server source; desktop releases are coordinated separately in `ahmad-fatayerji/veil`.

Run cargo fmt --all -- --check, cargo clippy --all-targets --locked -- -D warnings,
cargo test --locked, Compose configuration validation and relevant Docker integration
tests. Wait for Server CI gate. Describe validation and internet/native acceptance
limits in the PR. Container publication is explicit through Publish server container;
never publish secrets or claim a local test proves universal internet connectivity.

## Coordinated compatibility maintenance

Every task assesses impact on the desktop/server contract before implementation:
requests/responses, admission, authentication, signaling, invitation formats, peer
negotiation, relay behavior and capabilities. Record this assessment in each PR.
When required, inspect current `ahmad-fatayerji/veil` source and its `AGENTS.md`,
implement a coordinated desktop PR into `develop`, and cross-link both PRs.
Required counterpart changes are part of completion, not an unspecified follow-up.
Verify each repository's canonical origin before fetching, creating worktrees or
pushing. Keep Windows native code and desktop UI out of this server repository.

Review `src/compatibility.rs` and desktop
`packages/protocol/src/compatibility.ts` for every relevant change. Add a generation
for incompatible wire behavior; retain older generations only while their
implementations remain supported, and explicitly remove obsolete support.
Package-version equality does not prove compatibility. Pure UI/documentation
changes do not need protocol bumps or release-version changes.
Update `protocol.md`, regression coverage and the server revision pinned in desktop
integration CI when required. Release preparation reviews supported generations
and server-before-client upgrade order. Source PRs do not authorize deployment,
container publication or desktop releases.

## Worktree lifecycle

On this machine every task worktree is a direct sibling under
`C:\Users\ahmad\Documents\CodeBase\veil project\Veil-app`.
Inspect worktrees at task startup and after completion. Automatically remove only
stale task worktrees whose PR is merged, all work is published, HEAD has no
subsequent unpublished commits, and no active task owns them. Verify PR state/head,
tracking, locks, tracked/untracked changes and valuable ignored files. Disposable
build artifacts are removable only after verification; preserve credentials,
documents and unknown ignored files.

Resolve and verify the absolute target remains directly inside that parent. Run
`git worktree remove <verified-path>` from outside the target without `--force`,
then `git worktree prune`. Do not delete protected or remote branches. Never
remove an original checkout, stash/reset work to clear it, or recursively delete
an unchecked path. Preserve dirty, locked, active, open-PR, closed-unmerged and
uncertain worktrees. Keep the task worktree while its PR is open; report skipped
uncertain candidates. Use the same precautions on other machines with their
explicitly selected task-worktree parent.
