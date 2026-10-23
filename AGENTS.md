# Veil server repository rules

This public MIT repository contains server source, deployment and public protocol
only. Never copy signing keys, deployment secrets or unrelated desktop implementation here.
Read README.md, SECURITY.md and protocol.md before changing networking.

`ahmad-fatayerji/veil-server` is the canonical repository. Verify `origin` points
to `https://github.com/ahmad-fatayerji/veil-server.git` (or its SSH equivalent)
before fetching, creating task worktrees or pushing. Keep each task focused on
the user's request. Preserve authentication, invitation confidentiality, opt-in
public hosting limits, reserved credentialed-host capacity and relay exclusions.

Inspect git status, current branch and existing PR. Preserve uncommitted work.
For ordinary tasks fetch origin and create feature/<task> from origin/develop;
every task uses a separate worktree, even when the checkout is clean. Use Conventional
Commit titles and open PRs into develop. Do not push directly to protected branches,
force-push, bypass checks or merge without task authorization. main is reviewed
server source; desktop releases are coordinated separately in `ahmad-fatayerji/veil`.

For ordinary features and fixes, the user performs testing. Do not run local test
suites unless the user explicitly requests validation. Documentation-only changes
need lightweight formatting and consistency checks. When validation is requested,
use cargo fmt --all -- --check, cargo clippy --all-targets --locked -- -D warnings,
cargo test --locked, the protocol fixture, Compose validation and relevant Docker
integration. Required hosted CI still applies to every merge. Describe validation
and internet/native acceptance
limits in the PR. Publish server container automatically publishes validated main
commits to GHCR; a PR into main authorizes package publication, not deployment.
Manual publication is restricted to main. Never deploy a server from CI;
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
and server-before-client upgrade order. Ordinary source PRs do not authorize deployment,
container publication or desktop releases.

## Worktree lifecycle

On this machine the required worktree parent is
`C:\Users\ahmad\Documents\CodeBase\veil project\Veil-server`.
This outer folder is a container, not the Git checkout. Mirror the `Veil-app`
layout: the original server checkout is the inner `Veil-server`, and every task
worktree is its direct sibling under the outer folder:

```text
veil project/
  Veil-app/
    Veil/                         # Original desktop checkout
    Veil-<task>/                  # Desktop task worktree
  Veil-server/
    Veil-server/                  # Original server checkout; contains .git
    Veil-server-<task>/            # Server task worktree
```

Resolve and verify the destination parent before creating a worktree. Never put
server worktrees inside `Veil-app`, inside the original server checkout, directly
under `veil project`, or elsewhere under `CodeBase`. This rule applies to all
agents and task routes, including documentation, CI, release work and hotfixes.

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

## Required task workflow

`main` is the repository default and production source. Ordinary tasks start
from `develop` and target `develop`; a completed feature never authorizes a release.

1. Read this file and inspect `git status --short`, the current branch, existing
   task PR and `git worktree list` before editing. Preserve uncommitted work.
   Resume the same task only in its dedicated worktree.
2. For a new ordinary task, fetch origin and create `feature/<short-task-name>`
   from current `origin/develop`. Every task uses a separate Git worktree, even
   when the original checkout is clean. Create branch and worktree together with
   `git worktree add -b <branch> <path> <starting-ref>` before editing. Run edits,
   builds, tests, commits and pushes from that worktree. Never implement tasks in
   the original checkout or reuse a different task's worktree. Do not stash,
   reset or move another task's work to clear a checkout.
3. Stage only task files. Use Conventional Commit messages and PR titles:
   `feat:`, `fix:`, `docs:`, `ci:`, `test:`, `build:`, `refactor:`, `perf:`,
   `style:`, `chore:` or `revert:`, optionally scoped. Use `!` for breaking changes
   and describe their compatibility impact.
4. Validate only as requested and appropriate, following the guidance above.
   Report what actually ran and what remains unverified; never claim skipped
   checks passed. Docker integration requires a working Linux engine.
5. Push the task branch and open a PR into `develop`, with a concise description,
   desktop/server contract assessment and validation results. Use a draft if work
   remains. For associated issues, use `Closes #<number>` only when fully resolved
   and `Refs #<number>` for partial work; qualify cross-repository references.
   Verify references in the published PR body and GitHub's linked issues. Do not
   close issues manually just because a PR was opened.
6. For an ordinary handoff, report current PR/check status once; do not repeatedly
   poll or wait for CI. Leave the PR open unless merging is authorized. If fixing
   CI or merging is explicitly requested, address failures and review conversations
   and wait for **Server CI gate** on the exact current head.
7. Before an authorized merge, fetch origin and verify the task branch contains
   the latest target with `git merge-base --is-ancestor origin/<target> HEAD`.
   If behind, merge the updated target into the task branch, resolve conflicts,
   push, and wait for required checks on the updated head. Recheck immediately
   before merging. Squash ordinary task PRs; use a merge commit for promotion or
   synchronization between long-lived branches. Never force-push or bypass checks.

Ordinary task example, starting in the inner `Veil-server` checkout. Set
`$prBodyPath` to a temporary PR-description file outside the checkout:

```powershell
git remote -v
git status --short
git worktree list
git fetch origin
git worktree add -b feature/relay-fix ../Veil-server-relay-fix origin/develop
Set-Location ../Veil-server-relay-fix
# Implement the task; validate as requested and appropriate.
git add path/to/changed-file
git commit -m "fix: correct relay behavior"
git push -u origin feature/relay-fix
gh pr create --repo ahmad-fatayerji/veil-server --base develop --title "fix: correct relay behavior" --body-file $prBodyPath
```

Write multiline PR descriptions to a temporary file outside the checkout and
pass it with `--body-file`. Do not commit temporary PR text or credentials.

## Branch protections and publication boundaries

- `main` and `develop` require PRs, up-to-date branches, resolved conversations
  and **Server CI gate**, including for administrators. They reject force pushes
  and deletion. There is no mandatory second reviewer for the solo maintainer.
  Never disable protections, push directly, or delete these branches.
- Promote `develop` into `main` only when explicitly requested. Merging into
  `main` automatically runs **Publish server container**, validates the source,
  and publishes the GHCR image with full commit SHA and `latest` tags. Treat
  production promotion as a package-publication action requiring authorization.
  Use a merge commit to preserve ancestry. Bring released changes back through
  a PR into `develop` when necessary.
- Ordinary source/documentation work does not authorize manual publication,
  production promotion, release tags, desktop releases or deployment. Manual
  **Publish server container** runs on `main` require publication authorization.
- CI publishes the package only. Never connect to, restart or deploy an operator's
  server from CI. Server deployment is a separate explicitly authorized task.
- The desktop release coordinator belongs to `ahmad-fatayerji/veil`. Do not assume
  its Gitflow workflow names, version tooling or release routes exist here.
- GitHub automatically deletes eligible merged PR branches. Local worktree cleanup
  must not delete protected or remote branches.
- The handoff includes the branch/PR, validation and current check status, remaining
  work, and whether an authorized action published a package.
