# Android Build Analyzer Plugin

A Gradle plugin for Android build hygiene and reporting. It provides fast automated checks for API key exposure, APK composition, security misconfigurations, dependency freshness, and resource optimization.

## Release Notes (v1.1.0)

v1.1.0 is the trust-and-correctness release for the current roadmap.

Highlights:
- Reduced `DEBUG_APP_ID` false positives and added `applicationIdAllowlistPrefixes`
- Removed duplicate exported-component findings
- Fixed custom permission undefined detection
- Added baseline generation with `generateAnalysisBaseline`
- Added global suppressions with `suppressedRuleIds`
- Expanded dependency checks for BOMs and version catalogs
- Improved unused resource detection across code, XML, and manifest references
- Added Gradle TestKit functional coverage and targeted regression tests

Positioning:
- Use the plugin as a fast Android build hygiene and reporting layer
- Pair it with Android Lint, dependency scanners, and dedicated security tooling
- Do not position it as a full SAST replacement

## Implementation Status (v1.1)

Implemented in current branch:
- Security signal-quality fixes for app ID detection, exported-component deduping, and custom permission undefined detection
- `applicationIdAllowlistPrefixes` support for sample/dev namespaces
- Lazy task registration (`tasks.register`) in plugin wiring
- Report task incremental input fingerprints
- Global suppressions with `suppressedRuleIds`
- Baseline generation and filtering with `generateAnalysisBaseline` and `baselineFilePath`
- Dependency parsing for BOMs and version catalogs from `gradle/libs.versions.toml`
- Improved unused resource detection across code, XML, and manifest references
- Gradle TestKit functional tests for report generation and baseline behavior
- Regression tests for new security rules

Still important to keep in mind:
- The plugin is a heuristic analyzer, not a full SAST engine
- `analyzeApk` requires an existing APK artifact, but now runs after `assembleDebug`/`assembleRelease` when invoked in the same Gradle command
- Dependency checks depend on Maven metadata availability

See `docs/ROADMAP_v1.1.md` for detailed milestone tracking.

## Features

### 1. API Key Detection
Automatically scans your source code to detect hardcoded API keys and secrets that should never be committed to version control.

**Detected Key Types:**
- AWS Access Keys (AKIA/ASIA prefix)
- Firebase API Keys (AIza prefix)
- Stripe API Keys
- Google API Keys
- Generic API Keys (api_key= patterns)
- Private Keys (RSA/EC/DSA)

**Severity Levels:**
- **HIGH**: AWS keys, Firebase keys, Stripe keys, Private keys
- **MEDIUM**: Generic API keys

### 2. APK Analysis
Analyzes your built APK to understand its composition and identify optimization opportunities.

**Shows breakdown by:**
- DEX Bytecode (Dalvik/ART)
- Resources Table (resources.arsc)
- Native Libraries (lib/)
- Android Resources (res/)
- Assets (assets/)
- META-INF (signing files)
- XML Files

### 3. Security Check
Identifies common security vulnerabilities in your Android project.

**Key Feature: Actionable Fix Suggestions**
Each security finding includes specific fix suggestions with code examples:
- Network Security Config XML template
- HTTPS URL replacements
- Permission attribute examples
- ProGuard rules snippets

**Build Configuration Checks:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Debug Enabled in Release | HIGH | debuggable=true in release build |
| ProGuard/R8 Disabled | HIGH | minifyEnabled=false in release |
| Debug App ID | MEDIUM | Application ID contains .debug or .test |

**Manifest Security Checks:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Manifest Debuggable | HIGH | android:debuggable="true" in manifest |
| Allow Backup | MEDIUM | android:allowBackup="true" |
| Cleartext Traffic | MEDIUM | android:usesCleartextTraffic="true" |
| Exported Component | LOW | Exported without permission |

**Permission Analysis:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Dangerous Permission | HIGH/MEDIUM | Dangerous permissions (READ_SMS, CAMERA, etc.) |
| Permission Not Defined | MEDIUM | Uses undefined custom permission |

**Component Security:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Exported Service | MEDIUM | Service exported without permission |
| Exported Receiver | MEDIUM | Broadcast receiver exported without permission |
| Exported Provider | HIGH | Content provider exported without permission |

**Intent Filter Security:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Intent Filter Data Exposure | LOW | Intent filter may expose data |

### 4. Network Security
Analyzes network security configuration and detects insecure HTTP URLs.

**Manifest Checks:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Missing Network Security Config | MEDIUM | No network security config found |
| Cleartext Traffic Allowed | MEDIUM | HTTP traffic allowed in manifest |

**Code Analysis:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Insecure HTTP URL | MEDIUM | HTTP URL found in source code |
| No Certificate Pinning | LOW | No certificate pinning detected |

### 5. ProGuard/R8 Analysis
Analyzes ProGuard/R8 configuration for best practices when code obfuscation is enabled.

**Checks:**
- **Missing rules file**: Detects when proguard-rules.pro is missing
- **Rules quality check**: Validate ProGuard rules
- **Missing -keepclassmembers**: Check for model class protection
- **Library rules validation**: Verify proper rules for common libraries (OkHttp, Retrofit, Gson, RxJava, etc.)

**Actionable Fix Suggestions:**
Each finding includes specific code snippets to fix the issue:
- Suggested ProGuard rules to add
- Example -keepclassmembers patterns
- Template for new proguard-rules.pro files

### 6. Resource Analysis
Optimizes your app's resources to reduce APK size.

**Checks:**
- **Unused Resources**: Finds value resources not referenced in code, XML resources, or manifest
- **Duplicate Strings**: Identifies duplicate string values
- **Oversized Images**: Flags images larger than 1MB

### 7. Dependency Version Check
Detects outdated dependencies from multiple sources:
- build script literal coordinates (`implementation`, `api`, `testImplementation`, etc.)
- BOM coordinates declared with `platform(...)` / `enforcedPlatform(...)`
- version catalog aliases and accessors (`alias(libs....)`, `libs.okhttp`) resolved from `gradle/libs.versions.toml`

- Network calls use a 5-second timeout and fail gracefully when Maven Central is unreachable
- Falls back to Google Maven metadata when Maven Central has no result
- Pre-release versions (`-alpha`, `-beta`, `-RC`) in the latest version are skipped to avoid false positives

### 8. Gradle Properties Check
Checks `gradle.properties` for missing Gradle build optimization settings.

| Issue | Suggested Fix |
|-------|--------------|
| Parallel Execution Disabled | `org.gradle.parallel=true` |
| Build Cache Disabled | `org.gradle.caching=true` |
| Configuration Cache Disabled | `org.gradle.configuration-cache=true` |
| Low or Missing JVM Heap | `org.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=512m` |
| File System Watching Disabled | `org.gradle.vfs.watch=true` |

### 9. Multi-format Reports
Generates three report files in parallel:

| File | Format | Use case |
|------|--------|----------|
| `report.html` | HTML | Human review in browser |
| `report.json` | JSON | Scripting, dashboards, custom tooling |
| `report.sarif` | SARIF 2.1.0 | GitHub Advanced Security, IDE integration |

**GitHub Advanced Security integration:** Upload `report.sarif` as a code scanning result to surface findings directly in pull request diffs:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: app/build/reports/analyzer/report.sarif
```

## Requirements

- Android Gradle Plugin 8.2.2+
- Kotlin 1.9.22+
- Java 17+
- Gradle 8.2+

## Installation

### Gradle Plugin Portal (Recommended)

```kotlin
// settings.gradle.kts
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
```

```kotlin
// build.gradle.kts
plugins {
    id("com.android.application")
    id("io.github.davideagostini.analyzer") version "1.1.0"
}
```

### Snapshot Build

```kotlin
// settings.gradle.kts
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven { url = uri("https://repo.maven.apache.org/maven2/") }
    }
}
```

## Configuration

Configure the plugin in your `build.gradle.kts`:

```kotlin
androidBuildAnalyzer {
    // Enable/disable the analyzer
    enabled = true

    // Security checks
    checkDebuggable = true      // Check for debuggable=true in release
    checkMinifyEnabled = true  // Check for minifyEnabled=true in release
    checkAllowBackup = true    // Check for allowBackup in manifest

    // Report configuration
    reportPath = "build/reports/analyzer"  // Custom report path

    // Build behavior
    // When true, throws a GradleException if any HIGH severity finding is detected
    // Enforced in: detectApiKeys and securityCheck tasks
    failOnCriticalIssues = false

    // Exclude paths from all file scanning tasks (API key detection, HTTP URL scan, cert pinning)
    // Any file whose relative path contains one of these substrings is skipped
    excludePaths = listOf("src/test", "src/androidTest")

    // Allow sample/dev namespaces to skip DEBUG_APP_ID findings
    applicationIdAllowlistPrefixes = listOf("com.example.")

    // Suppress selected rules globally
    suppressedRuleIds = listOf("UNUSED_RESOURCE")

    // Optional baseline file with known findings
    baselineFilePath = "android-build-analyzer-baseline.json"

    // Custom API key patterns (optional)
    apiKeyPatterns = listOf(
        "(AKIA|ASIA)[A-Z0-9]{16}",
        "AIza[0-9A-Za-z\\-_]{35}"
    )
}
```

## Usage

### Run Full Analysis

```bash
./gradlew analyze
```

This will:
1. Run all analysis tasks in parallel
2. Generate HTML report at `build/reports/analyzer/report.html`

> **Note:** `analyzeApk` scans whatever APK already exists in `build/outputs/apk/`. It does not trigger a full build automatically, but if you run `./gradlew assembleRelease analyzeApk` or `./gradlew assembleDebug analyzeApk`, the analysis task now waits for the assemble task in the same invocation.

### Generate a Baseline

```bash
./gradlew generateAnalysisBaseline
```

This writes a JSON baseline file that suppresses the current findings on subsequent runs.

### Recommended CI Adoption

1. Run `./gradlew analyze`
2. Review the highest-signal findings first
3. Generate a baseline for existing accepted issues
4. Use `suppressedRuleIds` only for rules that are intentionally noisy or not relevant
5. Let CI fail only on new critical issues once the baseline is stable

### Run Individual Tasks

```bash
# API Key Detection
./gradlew detectApiKeys

# APK Analysis
./gradlew analyzeApk

# Security Check
./gradlew securityCheck

# Resource Analysis
./gradlew analyzeResources

# Generate Report
./gradlew generateAnalysisReport
```

### View Report

Open `app/build/reports/analyzer/report.html` in your browser.

## Project Structure

```
android-build-analyzer/
├── src/main/kotlin/
│   └── com/davideagostini/analyzer/
│       ├── AndroidBuildAnalyzerPlugin.kt    # Main plugin class
│       ├── AndroidBuildAnalyzerExtension.kt # Configuration
│       └── tasks/
│           ├── ApiKeyDetectionTask.kt       # API key scanning
│           ├── ApkAnalysisTask.kt           # APK composition
│           ├── SecurityCheckTask.kt        # Security issues
│           ├── ResourceAnalysisTask.kt     # Resource optimization
│           └── ReportGeneratorTask.kt       # HTML report
├── test-app/                               # Test application
└── docs/                                   # Documentation
```

## Architecture

### Plugin Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     ./gradlew analyze                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 AndroidBuildAnalyzerPlugin                  │
│  - Registers extension                                     │
│  - Creates analysis tasks                                  │
│  - Orchestrates execution                                  │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌───────────┬───────────┬───────────┬───────────┐
        ▼           ▼           ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
   │ detect   │ │ analyze │ │security │ │analyze  │ │generate │
   │ ApiKeys │ │   Apk  │ │ Check   │ │Resources│ │ Report  │
   └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  HTML Report   │
                    │ build/reports/ │
                    │ analyzer/      │
                    └─────────────────┘
```

### Extension Configuration

The `androidBuildAnalyzer` extension provides:

| Property | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | Boolean | true | Enable/disable all checks |
| `checkDebuggable` | Boolean | true | Check debuggable flag |
| `checkMinifyEnabled` | Boolean | true | Check minifyEnabled |
| `checkAllowBackup` | Boolean | true | Check allowBackup |
| `reportPath` | String | build/reports/analyzer | Report location |
| `failOnCriticalIssues` | Boolean | false | Throws `GradleException` when any HIGH severity finding is found |
| `apiKeyPatterns` | List<String> | (default patterns) | Custom detection patterns |
| `srcDirs` | FileCollection | src/main/* | Directories to scan |
| `excludePaths` | List<String> | `[]` | Path substrings to exclude from file scanning (test dirs, examples, etc.) |

### New tasks

| Task | Description |
|------|-------------|
| `checkDependencyVersions` | Queries Maven Central for outdated dependencies |
| `checkGradleProperties` | Checks `gradle.properties` for missing optimizations |

## Best Practices

### 1. Run in CI/CD

Add to your CI pipeline:

```yaml
- name: Run Analyzer
  run: ./gradlew analyze

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: analyzer-report
    path: app/build/reports/analyzer/
```

### 2. Fail on Critical Issues

To fail builds on HIGH severity issues:

```kotlin
androidBuildAnalyzer {
    failOnCriticalIssues = true
}
```

### 3. Exclude False Positives

Use `excludePaths` to skip files or directories that produce noise (test fixtures, example code, generated files):

```kotlin
androidBuildAnalyzer {
    excludePaths = listOf(
        "src/test",
        "src/androidTest",
        "example/",
        "generated/"
    )
}
```

This applies to: API key detection, HTTP URL scanning, and certificate pinning checks.

## Example Output

```
==================================================
Security Check Results
==================================================
Found 3 issue(s): HIGH=1, MEDIUM=2, LOW=0

HIGH: DEBUG_ENABLED
   Release build type has debuggable=true. This allows debugging the release APK.
   Location: build.gradle (buildTypes.release.debuggable)

MEDIUM: DEBUG_APP_ID
   Application ID contains '.debug' or '.test', which may indicate a debug build configuration in production.
   Location: build.gradle (defaultConfig.applicationId)

MEDIUM: ALLOW_BACKUP_ENABLED
   Manifest has android:allowBackup="true" which allows app data backup.
   Location: AndroidManifest.xml (<application>)
```

## Troubleshooting

### Plugin Not Found

If you get "plugin not found", ensure the Gradle Plugin Portal is in your repositories:

```kotlin
pluginManagement {
    repositories {
        gradlePluginPortal()
    }
}
```

### Analysis Not Running

Ensure you have an Android application or library plugin applied:

```kotlin
plugins {
    id("com.android.application")  // or com.android.library
    id("io.github.davideagostini.analyzer")
}
```

### Report Not Generated

Check the `reportPath` configuration and ensure the directory is writable.

## Roadmap - Future Features

### Planned Features for Future Releases

#### 1. Extended API Key Detection
- **Twilio/SendGrid/Mailgun keys**: Detect more third-party service keys
- **OAuth tokens**: Detect OAuth access and refresh tokens
- **Database connection strings**: Find exposed database credentials
- **Suppression annotations**: Allow developers to suppress false positives

#### 2. DEX Analysis
- **Method count per DEX**: Analyze method count limits (64K)
- **DEX compression analysis**: Check compression effectiveness
- **Native library ABI breakdown**: Analyze native libraries by architecture

#### 3. Dependency Analysis
- **Outdated dependencies**: Check for available updates
- **Security vulnerabilities**: Integrate with CVE databases
- **Duplicate dependencies**: Find duplicate JAR files

#### 4. ProGuard/R8 Analysis ✅ IMPLEMENTED
- **Rules quality check**: Validate ProGuard rules ✅
- **Missing rules warning**: Suggest rules for common libraries ✅
- **Missing -keepclassmembers**: Check for model class protection ✅
- **Library rules validation**: Verify proper rules for common libraries (OkHttp, Retrofit, Gson, etc.) ✅

#### 5. Network Security ✅ IMPLEMENTED
- **Network Security Config**: Analyze security configuration ✅
- **HTTP URL detection**: Find cleartext HTTP URLs in code ✅
- **Certificate pinning**: Check for certificate pinning implementation ✅

#### 6. Enhanced Manifest Analysis ✅ IMPLEMENTED
- **Permission analysis**: Review permission usage ✅
- **Component security**: Detailed exported component analysis ✅
- **Intent filter security**: Check for intent filter vulnerabilities ✅

#### 7. CI/CD Integration ✅ PARTIALLY IMPLEMENTED
- **JSON export**: Machine-readable report format ✅
- **SARIF export**: GitHub Advanced Security integration ✅
- **Trend analysis**: Track issues across builds
- **Slack/Teams notifications**: Alert on critical issues

#### 8. Custom Rules Engine
- **User-defined patterns**: Allow custom regex rules
- **Rule categories**: Organize custom rules by type
- **Rule sharing**: Share rule sets between projects

#### 9. Build Cache Analysis
Analyzes Gradle build cache performance and provides optimization suggestions.

- **Cache hit/miss ratio**: Monitor build cache effectiveness
- **Task recompilation detection**: Identify tasks that rebuild unnecessarily
- **Cache size analysis**: Track cache growth over time
- **Suggestions**: Enable configuration cache, update Gradle wrapper

Example output:
```
📊 Cache Report
- Hit rate: 67% (should be >90%)
- Unnecessarily recalculated tasks: :app:compileDebugKotlin (3 times today)
- Suggestion: add org.gradle.caching=true in gradle.properties
```

#### 10. Dependency Health Check
Analyzes project dependencies for security vulnerabilities and outdated versions.

- **CVE vulnerability detection**: Check against GitHub Advisory Database
- **Outdated dependencies**: Compare with latest available versions
- **Unused dependencies**: Find implementation dependencies not used in code
- **Circular dependencies**: Detect circular dependency chains

Example output:
```
🔴 Security Alert: coil-kt 1.1.0 has CVE-2024-1234
🟡 Update Available: kotlin 1.8.0 → 1.9.22
⚠️ Unused: implementation 'androidx.recyclerview:recyclerview' (not found in code)
```

#### 11. Task Execution Breakdown
Provides detailed timing analysis of build tasks to identify bottlenecks.

- **Task timeline**: Breakdown of each task during build
- **Slowest tasks**: Identify tasks like kapt, dex, merge resources
- **Parallel execution efficiency**: Analyze parallel vs sequential execution
- **Config vs Execution time**: Separate configuration time from execution time

Example output:
```
⏱️ Build Breakdown (last: 4m 23s)
- Configuration: 12s
- :app:kaptGenerateDebugKotlin: 1m 45s (42%)
- :app:dexDebug: 58s (23%)
- :app:mergeDebugResources: 32s (12%)
💡 Suggestion: enable kapt incremental=false if not using KSP
```

---

## Contributing

Contributions are welcome! To add new features:

1. Create a new task class extending `DefaultTask`
2. Register it in `AndroidBuildAnalyzerPlugin`
3. Add findings to the report in `ReportGeneratorTask`

## License

MIT License - see LICENSE file for details.

## Credits

Developed by [Davide Agostini](https://github.com/davideagostini)
