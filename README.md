# Android Build Analyzer ⚡

Fast Android build hygiene and reporting for CI and local checks.

[![Gradle](https://img.shields.io/badge/Gradle-8.x-blue?style=flat-square)](https://gradle.org)
[![AGP](https://img.shields.io/badge/Android%20Gradle%20Plugin-8.x-green?style=flat-square)](https://developer.android.com/studio/build)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9.x-purple?style=flat-square)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/davideagostini/android-build-analyzer?style=flat-square)](https://github.com/davideagostini/android-build-analyzer)

---

## Why?

Every Android developer faces these problems:

- ⚠️ **Accidentally committed API keys?** — It happens more often than you'd think
- 📦 **APK too big?** — Don't know what's bloating it
- 🔒 **Release without ProGuard?** — Security risk
- 📝 **Unused resources?** — Wasting space

**Android Build Analyzer** catches all of this — automatically.

---

## Features

- **API Key Detection**: Scans source files for exposed API keys (AWS, Firebase, generic API keys, private keys, Stripe, Google)
- **APK Composition Analysis**: Breaks down APK size by component (DEX, resources, assets, native libraries)
- **Security Best Practices**: Checks for debug flags, ProGuard/R8, allowBackup, cleartext traffic
- **Resource Analysis**: Finds unused resources (code + XML references), duplicate strings, oversized images
- **Dependency Version Check**: Checks outdated dependencies from build scripts, BOMs, and version catalogs using Maven Central with Google Maven fallback
- **Gradle Properties Check**: Detects missing build optimizations (parallel execution, build cache, configuration cache, JVM heap, VFS watching)
- **Suppressions and Baselines**: Supports global rule suppressions and a generated baseline file for known findings
- **Multi-format Reports**: Generates `report.html`, `report.json` and `report.sarif` (SARIF 2.1.0 for GitHub Advanced Security)

---

## What's New in v1.1.0

v1.1.0 is a trust-and-correctness release focused on reducing noise, improving Gradle integration, and making CI adoption easier.

Highlights:
- Reduced false positives in `DEBUG_APP_ID` detection
- Added `applicationIdAllowlistPrefixes`
- Removed duplicate exported-component findings
- Fixed custom permission undefined detection
- Added baseline generation and global rule suppressions
- Expanded dependency checks for BOMs and version catalogs
- Improved unused resource detection across code, XML, and manifest references
- Added regression and functional test coverage

This release makes the plugin more reliable as an early-warning hygiene check for Android projects.

---

## Release Status (v1.1.0)

Implemented in this release:
- Reduced `DEBUG_APP_ID` false positives by switching to segment-based detection (for example `com.example.testapp` is no longer flagged)
- Added `applicationIdAllowlistPrefixes` for sample/dev namespaces that should not be flagged
- Removed duplicate/noisy generic exported-component findings
- Fixed custom permission undefined detection logic
- Migrated plugin wiring from eager task creation to lazy task registration (`tasks.register`)
- Added report task input fingerprints to improve incremental correctness
- Added baseline generation and finding filtering via `suppressedRuleIds` and `baselineFilePath`
- Expanded dependency parsing to BOMs and `gradle/libs.versions.toml`
- Improved unused resource detection to account for code, XML, and manifest references
- Added Gradle TestKit functional coverage for report generation and baseline suppression
- Added rule regression tests for app ID, custom permission detection, and exported activity checks

Current positioning:
- Fast Android build hygiene and reporting plugin
- Best used as an early CI guardrail alongside Android Lint and dedicated security tooling

Known limitations:
- Several checks are still heuristic, especially API key detection and some manifest/string scans
- `analyzeApk` analyzes an APK that already exists in `build/outputs/apk/`; it does not assemble one automatically, but it now runs after `assembleDebug`/`assembleRelease` when those tasks are requested in the same Gradle invocation
- Dependency version checks require network access to Maven repositories and fail gracefully when metadata is unavailable

See `docs/ROADMAP_v1.1.md` for detailed milestones and status.

---

## Managing Noise

If some findings are expected in your project, adopt the plugin incrementally:

- Use `suppressedRuleIds` to disable specific rules globally
- Use `generateAnalysisBaseline` to accept current findings and focus on regressions
- Use `applicationIdAllowlistPrefixes` for sample or sandbox app IDs that should not trigger `DEBUG_APP_ID`

Recommended adoption flow:
1. Run `./gradlew analyze`
2. Review the highest-signal findings
3. Generate a baseline for known issues
4. Keep CI focused on new regressions

---

## Installation

### Option 1: Gradle Plugin Portal (Recommended)

Add the plugin to your `settings.gradle.kts`:

```kotlin
plugins {
    id("io.github.davideagostini.analyzer") version "1.1.0"
}
```

Or in Groovy `settings.gradle`:

```groovy
plugins {
    id 'io.github.davideagostini.analyzer' version '1.1.0'
}
```

### Option 2: Maven Local

If the plugin is not yet published to the Gradle Plugin Portal, you can use Maven Local.

**Step 1: Build and publish the plugin locally**

```bash
git clone https://github.com/davideagostini/android-build-analyzer.git
cd android-build-analyzer
./gradlew clean publishToMavenLocal
```

**Step 2: Add the plugin to your project**

In your `settings.gradle.kts`:

```kotlin
pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
}

plugins {
    id("io.github.davideagostini.analyzer") version "1.1.0"
}
```

**Step 3: Configure the plugin**

Add to your `app/build.gradle.kts`:

```kotlin
androidBuildAnalyzer {
    enabled = true
    checkDebuggable = true
    checkMinifyEnabled = true
    checkAllowBackup = true
    reportPath = "build/reports/analyzer"
    failOnCriticalIssues = false
}
```

---

## Usage

Run the full analysis:

```bash
./gradlew analyze
```

The HTML report will be generated at `app/build/reports/analyzer/report.html`.

### Available Tasks

| Task | Description |
|------|-------------|
| `./gradlew analyze` | Run all checks & generate all reports |
| `./gradlew detectApiKeys` | Scan for exposed API keys |
| `./gradlew analyzeApk` | Analyze APK composition |
| `./gradlew securityCheck` | Run security checks |
| `./gradlew analyzeResources` | Find unused resources |
| `./gradlew checkDependencyVersions` | Check for outdated dependencies |
| `./gradlew checkGradleProperties` | Check Gradle optimizations |
| `./gradlew generateAnalysisReport` | Generate HTML, JSON, SARIF reports |
| `./gradlew generateAnalysisBaseline` | Generate a baseline JSON file from current findings |

---

## Configuration

The plugin provides configurable options via the `androidBuildAnalyzer` extension:

```kotlin
androidBuildAnalyzer {
    enabled = true                    // Enable/disable the plugin
    apiKeyPatterns = [...]            // Custom regex patterns for API keys
    checkDebuggable = true           // Check for debuggable flag in release
    checkMinifyEnabled = true        // Check for minifyEnabled in release
    checkAllowBackup = true          // Check for allowBackup in manifest
    reportPath = "build/reports/analyzer"  // Output path for reports
    failOnCriticalIssues = false     // Fail build on HIGH severity issues
    excludePaths = []                // Paths to skip during scanning
    applicationIdAllowlistPrefixes = listOf("com.example.")
    suppressedRuleIds = listOf("UNUSED_RESOURCE")
    baselineFilePath = "android-build-analyzer-baseline.json"
}
```

### Suppressions and Baselines

Use suppressions when a rule is intentionally not relevant for a project:

```kotlin
androidBuildAnalyzer {
    suppressedRuleIds = listOf("UNUSED_RESOURCE", "ALLOW_BACKUP_ENABLED")
}
```

Use a baseline when you want to adopt the plugin incrementally:

```bash
./gradlew generateAnalysisBaseline
```

Then keep the generated `android-build-analyzer-baseline.json` in the project root, or point the plugin to a custom path:

```kotlin
androidBuildAnalyzer {
    baselineFilePath = "config/analyzer/baseline.json"
}
```

### Default API Key Patterns

The plugin detects these patterns by default:

| Pattern Type | Regex |
|-------------|-------|
| AWS Keys | `(AKIA\|ASIA)[A-Z0-9]{16}` |
| Firebase | `AIza[0-9A-Za-z\\-_]{35}` |
| Generic API Key | `[aA][pP][iI][-_]?[kK][eE][yY].*['"][a-zA-Z0-9]{20,}['"]` |
| Private Keys | `-----BEGIN (RSA \|EC \|DSA )?PRIVATE KEY-----` |
| Stripe | `[sS][tT][rR][iI][pP][eE][_]?[pP][uU][bB][lL][iI][cC][_]?[kK][eE][yY]...` |
| Google API | `[gG][oO][oO][gG][lL][eE][_]?[aA][pP][iI][_]?[kK][eE][yY]...` |

---

## Output

### Console Output

The plugin outputs color-coded results to the console:

```
==================================================
API Key Detection Results
==================================================
Found 2 potential API key(s):
HIGH: app/src/main/java/com/example/ApiService.kt:15
   Pattern: AIza[0-9A-Za-z\-_]{35}
   Matched: AIzaS***yB7E
==================================================
Security Check Results
==================================================
Found 1 issue(s): HIGH=1, MEDIUM=0, LOW=0
HIGH: ProGuard/R8 Disabled
   Release build type does not have minifyEnabled=true.
   Location: build.gradle (buildTypes.release.minifyEnabled)
```

### Reports

Three files are generated in `build/reports/analyzer/`:

| File | Format | Use case |
|------|--------|----------|
| `report.html` | HTML | Human review in browser |
| `report.json` | JSON | Scripting, dashboards |
| `report.sarif` | SARIF 2.1.0 | GitHub Advanced Security |

---

## Requirements

- Gradle 8.x
- Android Gradle Plugin 8.x
- Kotlin 1.9.x
- Java 17+

---

## License

MIT License - See [LICENSE](LICENSE) file.

---

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
