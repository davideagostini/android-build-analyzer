# Changelog

## v1.1.0

### Added
- Baseline generation with `generateAnalysisBaseline`
- Global rule suppression with `suppressedRuleIds`
- Application ID allowlist support with `applicationIdAllowlistPrefixes`
- Functional Gradle TestKit coverage for report generation and baseline behavior
- Regression tests for security rule edge cases

### Changed
- Reduced `DEBUG_APP_ID` false positives by switching to segment-based detection
- Improved exported component checks to avoid duplicate findings
- Improved unused resource detection across code, XML, and manifest references
- Expanded dependency version checks to support BOMs and version catalogs
- Migrated plugin task wiring to lazy task registration
- Improved report incrementality and task correctness

### Fixed
- Custom permission undefined detection logic
- Incorrect HTTPS remediation suggestion for malformed repeated `http://` URLs
- `analyzeApk` task ordering when invoked together with `assembleDebug` or `assembleRelease`

### Notes
- `analyzeApk` does not build an APK automatically; run `assembleDebug` or `assembleRelease` first if needed
- Dependency checks are best-effort and depend on repository metadata availability
- Android Build Analyzer is intended as a fast build hygiene and reporting layer, not a full SAST replacement
