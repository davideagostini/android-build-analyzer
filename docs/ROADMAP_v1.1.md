# Android Build Analyzer v1.1 Roadmap

## Current Status (as of this branch)
- Completed: 1.1, 1.2, 1.3, 2.1, 2.2, 3.1, 3.2, 4.1, 4.2, 5.1, 5.2
- Final outcome: v1.1.0 is ready as a trust-and-correctness release with baseline support, improved dependency/resource coverage, and verified regression coverage

## Release Notes Summary
- Less noisy security findings through tighter app ID and exported-component checks
- Better Gradle behavior through lazy task registration and improved report incrementality
- Better team adoption through suppressions, baselines, and clearer product positioning
- Broader practical coverage through BOM/version-catalog dependency support and better unused resource detection
- Stronger confidence through regression tests and Gradle TestKit functional tests

## Goal
Increase trust and adoption by reducing false positives, improving Gradle plugin quality, and enabling reliable CI usage.

## Non-goals for v1.1
- Full SAST replacement
- Deep binary reverse engineering
- Full dependency graph vulnerability engine

## Success Metrics
- Reduce false positives in security checks by at least 50% on fixture projects
- Keep end-to-end `analyze` runtime under 15 seconds on sample app (cold network excluded)
- Achieve stable CI runs with deterministic report generation and no stale outputs

## Milestone 1: Signal Quality (High Priority)

### 1.1 Fix App ID false positives
- Status: Done
- Problem: `DEBUG_APP_ID` currently flags any ID containing `.test` or `.debug` as substring
- Change:
  - Flag only suffix-like patterns (`.debug`, `.test`) or segment tokens (`debug`, `test`) based on dot-separated parts
  - Add explicit allowlist for common sample namespaces (`com.example.*`) when configured
- Acceptance:
  - `com.example.testapp` is not flagged by default
  - `com.mycompany.myapp.debug` is flagged

### 1.2 Remove duplicate exported-component findings
- Status: Done
- Problem: generic exported component check emits duplicate/noisy findings
- Change:
  - Parse manifest tags (`activity/service/receiver/provider`) once
  - Emit one finding per component with stable location and name
  - Keep dedicated checks for service/receiver/provider and avoid overlap
- Acceptance:
  - Same component cannot generate duplicated generic findings

### 1.3 Fix custom permission undefined check
- Status: Done
- Problem: condition is effectively unreachable for custom permission detection
- Change:
  - Parse `<uses-permission android:name="...">` and `<permission android:name="...">`
  - Flag only non-`android.permission.*` permissions that are used and not declared in manifest/package
- Acceptance:
  - Custom undeclared permissions are detected
  - Standard Android permissions are not reported as undefined

## Milestone 2: Gradle Plugin Correctness (High Priority)

### 2.1 Incremental/report correctness
- Status: Done
- Problem: report generation may use stale data because task inputs are internal-only
- Change:
  - Declare report task inputs explicitly from upstream findings as serialized JSON strings/files
  - Keep output directory declaration strict
- Acceptance:
  - Re-running with changed findings regenerates report
  - Re-running without changes is up-to-date

### 2.2 Modern lazy registration
- Status: Done
- Change:
  - Move from `tasks.create` to `tasks.register`
  - Wire dependencies with providers
- Acceptance:
  - Configuration avoidance works in Gradle build scans

## Milestone 3: Tests and CI Confidence (Medium Priority)

### 3.1 Add Gradle TestKit integration tests
- Status: Done
- Fixture projects:
  - clean app
  - intentionally vulnerable app
  - mixed false-positive regression app
- Acceptance:
  - `analyze` output and report assertions pass in CI

### 3.2 Rule regression tests
- Status: Done
- Add tests for:
  - app ID rule edge cases
  - exported component deduping
  - custom permission declared/undeclared scenarios

## Milestone 4: Dependency and Resource Checks (Medium Priority)

### 4.1 Dependency source coverage
- Status: Done
- Parse:
  - `libs.versions.toml`
  - version refs and catalog aliases
  - BOM usage hints
- Support Google Maven lookups for AndroidX artifacts

### 4.2 Resource accuracy
- Status: Done
- Improve unused resource detection:
  - include XML usages (`@string/...`, `@color/...`)
  - optional R8/resource-shrinker integration hints

## Milestone 5: UX and Positioning (Medium Priority)

### 5.1 Rule metadata and suppressions
- Status: Done
- Add rule IDs and suppression config in extension
- Add baseline file support for known findings

### 5.2 Product positioning
- Status: Done
- Update README language to: "fast Android build hygiene + reporting"
- Document known limitations explicitly

## Delivery Summary
1. Signal quality issues were fixed first to improve trust in findings
2. Gradle task wiring and report incrementality were stabilized
3. Test coverage was expanded with regression and functional tests
4. Dependency/resource coverage was broadened without changing the plugin's lightweight positioning
5. Suppressions, baselines, and product documentation were aligned for real CI adoption

## Release Positioning
- v1.1.0: final trust-and-correctness release for the current roadmap
- Recommended messaging: "fast Android build hygiene + reporting"
- Recommended usage: complement Android Lint, dependency scanners, and deeper security tooling
