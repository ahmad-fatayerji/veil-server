# Veil server agent workflow

This public MIT repository contains server source, deployment and public protocol
only. Never copy private Veil desktop source, signing keys or deployment secrets.
Read README.md, SECURITY.md and protocol.md before changing networking.

Inspect git status, current branch and existing PR. Preserve uncommitted work.
For ordinary tasks fetch origin and create feature/<task> from origin/develop;
use a separate worktree when another task owns the checkout. Use Conventional
Commit titles and open PRs into develop. Do not push directly to protected branches,
force-push, bypass checks or merge without task authorization. main is reviewed
server source; desktop releases are a separate private-repository process.

Run cargo fmt --all -- --check, cargo clippy --all-targets --locked -- -D warnings,
cargo test --locked, Compose configuration validation and relevant Docker integration
tests. Wait for Server CI gate. Describe validation and internet/native acceptance
limits in the PR. Container publication is explicit through Publish server container;
never publish secrets or claim a local test proves universal internet connectivity.
