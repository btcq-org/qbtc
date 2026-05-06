---
description: Approve and merge a GitHub pull request. Usage: /approve-and-merge-pr [PR number]
---

Approve and merge a GitHub pull request using `gh`.

## Steps

1. **Get PR number** from args. If no PR number provided, run `gh pr list` and ask the user which PR to act on.

2. **Show PR details**: Run `gh pr view <number>` to display the title, state, author, and branch before taking any action.

3. **Ask merge strategy**: Ask the user which merge strategy to use — squash (default), merge commit, or rebase — unless they already specified one.

4. **Approve**: Run `gh pr review <number> --approve` with an optional body ("LGTM" if none given).

5. **Merge**: Run the merge with the chosen strategy:
   - Squash: `gh pr merge <number> --squash --auto`
   - Merge commit: `gh pr merge <number> --merge --auto`
   - Rebase: `gh pr merge <number> --rebase --auto`

6. **Confirm**: Report success with the PR URL and what was done.

## Notes

- Always show the PR details (step 2) before approving — never skip this.
- If the PR is already approved or merged, say so and stop.
- `--auto` enables auto-merge: the PR merges automatically once all required checks pass.
- If the repo does not have auto-merge enabled, drop the `--auto` flag and merge directly.
- Do not approve your own PRs (gh will error; surface that clearly).
