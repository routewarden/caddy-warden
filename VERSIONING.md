# RouteWarden Plugin Versioning & Release Guide

This document explains how versioning is managed for the **RouteWarden** Caddy v2 plugin repository (`github.com/routewarden/caddy-warden`).

---

## 1. Single Source of Truth (`version.json`)

The canonical version of RouteWarden is stored in [`version.json`](version.json) at the repository root:

```json
{
  "version": "v1.2.0"
}
```

Whenever you prepare a release, update this file or use the automated synchronization script.

---

## 2. Semantic Versioning Specification

RouteWarden follows standard [Semantic Versioning (SemVer 2.0.0)](https://semver.org/):

$$\text{v}\mathbf{MAJOR}.\mathbf{MINOR}.\mathbf{PATCH}$$

- **MAJOR** (`v1.0.0`): Breaking architectural changes, incompatible Caddyfile syntax, or modified middleware behaviors.
- **MINOR** (`v0.3.0`): Backwards-compatible features (e.g., new response modes, novel anti-evasion rules, new matching options).
- **PATCH** (`v0.2.5`): Backwards-compatible bug fixes, security hardening, or performance optimizations.

---

## 3. Automated Version Synchronization

When a release is published, documentation and example manifests must reference the exact Git tag.

To automate this across all files, run [`scripts/update-version.sh`](scripts/update-version.sh):

### Mode A: Read directly from `version.json`
Update the version inside [`version.json`](version.json), then run:
```bash
./scripts/update-version.sh
```

### Mode B: Pass target version via CLI
Pass the new version as an argument. The script will automatically update `version.json` and sync all files:
```bash
./scripts/update-version.sh v0.2.5
```

### What gets synchronized:
1. **[`version.json`](version.json)**: Canonical single source of truth.
2. **[`README.md`](README.md)**: Reference tags and build instructions.

---

## 4. Step-by-Step Release Workflow

### Step 1: Run Quality & Security Checks
Verify all Go tests pass with race detection:
```bash
go test -v -race ./...
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

### Step 2: Update Version Strings
Run the update script:
```bash
./scripts/update-version.sh v0.2.5
```

### Step 3: Review Diff & Commit
```bash
git diff
git add -u
git commit -m "chore: release v0.2.5"
```

### Step 4: Tag & Push
Caddy plugins built with `xcaddy` and Go modules resolve via **Git tags**:
```bash
git tag v0.2.5
git push origin main --tags
```

---

## 5. Documentation Repository Coordination

The documentation wiki is maintained in the dedicated repository:  
👉 [**`github.com/routewarden/docs`**](https://github.com/routewarden/docs) (served at [routewarden.github.io/docs](https://routewarden.github.io/docs/)).

When publishing minor or major versions, update the version registry in the docs repository to freeze historical version archives.
