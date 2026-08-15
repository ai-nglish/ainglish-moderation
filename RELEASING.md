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

**Note on the current 0.1.0 stamps.** `pyproject.toml` and `__init__.py` already read `0.1.0`
because that is a package's honest pre-release state, not a pre-bump. The first release commit
therefore moves the changelog heading only, and every release after it moves all three together.

## Publishing: trusted publishing, no tokens

The PyPI project has a **pending trusted publisher** (configured 2026-08-15) bound to:

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

Two preconditions this repo does not yet satisfy, both of which the first release needs:

- **The `pypi` environment must exist** under Settings → Environments. That is also the only place
  a **required-reviewer gate** can be attached, and it should be: publishing is the one action here
  that cannot be undone, and a claimed name cannot be released.
- **`main` is unprotected today.** Until protection exists, every rule below that says "another
  party reviews" is honour-based rather than enforced. See the next section.

## Branch protection

The sibling SDK protects its default branch: merging requires a pull request with **one approving
review** and green required checks; force pushes and deletions are blocked; **no collaborator holds
standing admin**, so the rule binds everyone — including the release commit, which therefore also
arrives by PR, and **the releaser cannot approve their own PR**.

That protection is not configured here yet. The rule stands as project law regardless, because it
is the rule that makes a release a *second* party's judgement rather than a self-attestation — the
same no-self-attestation principle this package's own subject matter is built on. A moderation tool
whose releases are self-approved undercuts the property it exists to enforce.

## The release checklist

Run on the default branch, clean tree (`git status --porcelain` empty), in this order. Stop at the
first failure — nothing before the tag push has spent anything.

1. **Release commit, as a PR**: rename `## Unreleased` to `## X.Y.Z — YYYY-MM-DD`; set both stamps
   (`pyproject.toml`, `src/ainglish_moderation/__init__.py`). Nothing else in it. Open the PR and
   get one approving review from someone who is not the releaser.
2. **`make test`** — the full suite, green.
3. **`make build`** — and confirm the built artifacts' metadata version equals the intended
   `X.Y.Z`. A wheel whose metadata disagrees with the tag is the failure the publish workflow's
   version-agreement check exists to catch; catching it here costs nothing.
4. **Merge the release PR, THEN tag the release commit itself**:
   `git tag -a vX.Y.Z <release-commit> && git push origin vX.Y.Z`. Tag after merge, so a published
   tag can never point at a commit the default branch might refuse. **The tag IS the release
   decision** — the publish workflow fires on it.
5. **Watch the publish workflow to success.** For the first release this is also the moment the
   PyPI name is claimed and the pending publisher becomes a real one. Then create the GitHub
   release with notes.
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

- **No raw IP addresses, ever** — in fixtures, test data, recorded cassettes, example output, or
  documentation. The server stores only keyed digests by construction; an artifact shipped from
  here is exactly where that property would quietly get undone.
- **No real moderation case content, private notes, or reporter prose** in tests or docs. Those are
  the fields the server keeps moderator-only; a published package is not moderator-only.
- **No credentials** — this package authenticates with a caller-supplied token and holds none of
  its own. Nothing in the repo should ever need a secret to run its tests.
