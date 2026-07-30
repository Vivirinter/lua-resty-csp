# Contributing

## Development

```bash
make test
make test-resty
make test-nginx
```

## Pull requests

1. Keep changes focused.
2. Add or update tests for behavior changes.
3. Update `CHANGELOG.md` under `[Unreleased]` or the next version section.
4. Use Conventional Commit messages when possible (`feat:`, `fix:`, `docs:`).

## Releases

1. Bump `dist.ini`, rockspec, and `_VERSION`.
2. Update `CHANGELOG.md`.
3. Push a tag `vX.Y.Z` to trigger the Release workflow.
4. Optional OPM publish: create a **classic** GitHub PAT with **only** `user:email` and `read:org` scopes (OPM rejects broader tokens). Store it as repository secret `OPM_GITHUB_TOKEN`, then re-run the Release workflow or run `opm upload` locally with matching `~/.opmrc`.
