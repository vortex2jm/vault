# Releasing

A release is a tag `vX.Y.Z` on `main`. Pushing it runs `.github/workflows/release.yml`, which checks that the tag matches the version in `Cargo.toml`, runs the tests, builds a static Linux binary and publishes the GitHub release, with that version's section of `CHANGELOG.md` as its notes.

1. On `develop`, set `version` in `Cargo.toml`, add the version's section to `CHANGELOG.md` with the release date, and commit (`chore: release vX.Y.Z`).
2. Push `develop`, open a pull request `develop → main`, wait for CI to pass, and merge it.
3. Tag the merge on `main` and push the tag:

   ```sh
   git checkout main && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

   Or on GitHub: *Releases → Draft a new release*, type `vX.Y.Z` under *Choose a tag* (it is created on `main`), and *Publish*. The workflow then adds the binary and the checksums to that release.
4. Check the release page: the notes, `vault-vX.Y.Z-x86_64-linux.tar.gz` and `SHA256SUMS`.

If the workflow fails before publishing (say, the tag and `Cargo.toml` disagree), fix it on `develop`, merge again, delete the tag (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`) and tag again.

## Versions

[Semantic Versioning](https://semver.org/): while the version is 0.x, a minor bump (0.2.0) may change commands; a patch (0.1.1) only fixes. The vault file format has a version of its own (see `docs/SECURITY.md`), and every release opens the files of all the earlier ones.
