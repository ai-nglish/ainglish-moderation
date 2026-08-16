# RELEASING.md — how a version number becomes a release

Adopted from `ai-nglish/ainglish`'s release law, which exists because two version numbers were
burned learning it. The invariants are the same here, and one is sharper: this project has never
published, so its **first tag claims the PyPI name `ainglish-moderation` permanently**. PyPI does
not release or reuse a project name after it is claimed.

Two facts make version numbers expensive:

1. **A pushed tag never moves.** Moving a published tag costs more than the gap it leaves.
2. **PyPI never accepts the same version twice**, even after a delete.

Together they mean any defect found *after* `git push origin vX.Y.Z` is unfixable in place — the
number is burned and the fix takes the next one.

## The rule that prevents most burns: NO PRE-BUMPS

**Feature PRs never touch the version.** Concretely, a PR must not:

- change `version` in `pyproject.toml`,
- change `__version__` in `src/ainglish_moderation/__init__.py`,
- add a `## X.Y.Z — date` heading to `CHANGELOG.md`.

Changelog entries for merged-but-unreleased work go under `## Unreleased` at the top of
`CHANGELOG.md` — where this repo already correctly puts them. The release commit, and only the
release commit, renames that heading to `## X.Y.Z — YYYY-MM-DD` and moves both version stamps, so
the number is claimed at the moment the chain below is about to prove it. A number that was never
claimed can never be burned.

## Publishing: trusted publishing, no tokens

The PyPI project has a **verified trusted publisher** (first successful publication: v0.1.1 on
2026-08-16) bound to:

| Field | Value |
|---|---|
| PyPI project | `ainglish-moderation` |
| Owner | `ai-nglish` |
| Repository | `ainglish-moderation` |
| Workflow filename | `publish.yml` |
| Environment | `pypi` |

Publication happens over GitHub OIDC — no API token exists, so no API token can leak. The four
values above must match the workflow **exactly**; a mismatch fails at publish time, not at setup
time. `publish.yml` is the *filename*, not the workflow's `name:` field.

The `pypi` environment exists only as the namespace bound into PyPI's trusted-publisher identity.
It deliberately has no required reviewers or wait timer, matching the sibling SDK: merging the
independently reviewed release PR and pushing its immutable version tag are the release decision,
and the tag starts publication without a second manual gate. The deployment branch policy remains
empty — a "protected branches only" policy would block deployments originating from tags, which
is how this workflow fires. Verify settings by read-back after changing them: a successful
environment update does not prove that omitted reviewer rules were cleared.

## Branch protection

The sibling SDK protects its default branch: merging requires a pull request with **one approving
review** and green required checks; force pushes and deletions are blocked; **no collaborator holds
standing admin**, so the rule binds everyone — including the release commit, which therefore also
arrives by PR, and **the releaser cannot approve their own PR**.

**`main` here is protected, and the enforced contract is:** pull request required with one
approving review; stale approvals dismissed on new pushes; **approval of the most recent push
required**, which is what actually stops a releaser approving their own release rather than leaving
it to good manners; conversation resolution required; force pushes and branch deletion blocked; and
**administrators included**, so no collaborator holds a standing bypass. Verified by attempting a
direct push and a force push from a full-admin account — both refused (`GH006`), `main` unmoved.

The required checks are `test (Python 3.9)` and `test (Python 3.12)`. Those exact job names are part
of the protection contract, so renaming a job without updating branch protection silently stops
satisfying the merge gate.

The rule this enforces is the reason it exists: a release should be a *second* party's judgement
rather than a self-attestation — the same no-self-attestation principle this package's own subject
matter is built on. A moderation tool whose releases are self-approved undercuts the property it
exists to enforce.

## The release checklist

Run on the default branch, clean tree (`git status --porcelain` empty), in this order. Stop at the
first failure — nothing before the tag push has spent anything.

1. **Release commit, as a PR**: rename `## Unreleased` to `## X.Y.Z — YYYY-MM-DD`, and **ensure
   both stamps equal `X.Y.Z`** (`pyproject.toml`, `src/ainglish_moderation/__init__.py`), editing
   them when they differ. Nothing else in it. Open the PR and get one approving review from someone
   who is not the releaser.
2. **`make test`** — the full suite, green.
3. **`make build`** — and confirm the built artifacts' metadata version equals the intended
   `X.Y.Z`. A wheel whose metadata disagrees with the tag is the failure the publish workflow's
   version-agreement check exists to catch; catching it here costs nothing.
4. **Merge the release PR, THEN tag the release commit itself**:
   `git tag -a vX.Y.Z <release-commit> && git push origin vX.Y.Z`. Tag after merge, so a published
   tag can never point at a commit the default branch might refuse. **The tag IS the release
   decision** — the publish workflow fires on it automatically, with no environment approval.
5. **Watch the publish workflow to success.** Then create the GitHub release with notes.
6. **Fresh-venv verification**: `pip install ainglish-moderation==X.Y.Z` in a new venv (allow a
   minute or two of PyPI propagation; retry, don't panic) and assert the release's **actual
   behaviour change** — for a CLI package, that the console entry point runs and the changed
   command does the changed thing — not merely that `__version__` prints the right string. A
   version string can be right while the artifact is wrong.
7. **Against a live server, for anything touching the moderation API**: confirm the released client
   still talks to `ainglish.org` — the endpoints this package wraps are moderator-gated, so a
   release that only ever ran against fixtures has not been shown to work against the surface it
   exists for.

A release is **done** when step 7 is green. "Tagged and on PyPI" is the middle of the chain, not
the end. If anything fails between the tag and the last step, the number is spent: fix forward,
take the next number, and leave a superseded warning on the burned release's notes.

## What this package must never publish

Ordinary release hygiene plus one domain-specific rule, because of what this client handles:

- **No real IP addresses.** No observed, production, or otherwise operational address may enter a
  tracked or published artifact — fixtures, test data, recorded cassettes, example output, or docs.
  **IANA-reserved documentation ranges are permitted in synthetic fixtures and tests**
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`): they identify no host and
  carry no personal data, and a valid literal is *required* to prove the property that matters —
  that the client accepts an operator's address and never prints it. A rule broad enough to ban
  those literals would ban the test that proves the guarantee, which is the opposite of the intent.
- **The server and export invariant stays absolute**, and is a different claim from the fixture
  rule above: a raw address supplied to a restriction is transformed on arrival, never persisted,
  never returned, and only a keyed fingerprint is ever serialised. Nothing shipped from this
  package may weaken that — an operational export is exactly where it would quietly get undone.
- **No real moderation case content, private notes, or reporter prose** in tests or docs. Those are
  the fields the server keeps moderator-only; a published package is not moderator-only.
- **No credentials** — this package authenticates with a caller-supplied token and holds none of
  its own. Nothing in the repo should ever need a secret to run its tests.
