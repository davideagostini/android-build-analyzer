# Android Build Analyzer ⚡

One command to secure your app and optimize your APK.

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
- **Resource Analysis**: Finds unused resources, duplicate strings, oversized images
- **Dependency Version Check**: Queries Maven Central to detect outdated `implementation`/`api` dependencies
- **Gradle Properties Check**: Detects missing build optimizations (parallel execution, build cache, configuration cache, JVM heap, VFS watching)
- **Multi-format Reports**: Generates `report.html`, `report.json` and `report.sarif` (SARIF 2.1.0 for GitHub Advanced Security)

---

## Installation

### Option 1: Gradle Plugin Portal (Recommended)

Add the plugin to your `settings.gradle.kts`:

```kotlin
plugins {
    id("io.github.davideagostini.analyzer") version "1.0.1"
}
```

Or in Groovy `settings.gradle`:

```groovy
plugins {
    id 'io.github.davideagostini.analyzer' version '1.0.1'
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
    id("io.github.davideagostini.analyzer") version "1.0.1"
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
