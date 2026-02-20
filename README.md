# Android Build Analyzer Plugin

A Gradle plugin for Android developers to detect security issues and analyze APK performance.

## Features

- **API Key Detection**: Scans source files for exposed API keys (AWS, Firebase, generic API keys, private keys, Stripe, Google)
- **APK Composition Analysis**: Breaks down APK size by component (DEX, resources, assets, native libraries)
- **Security Best Practices**: Checks for debug flags, ProGuard/R8, allowBackup, cleartext traffic
- **Resource Analysis**: Finds unused resources, duplicate strings, oversized images
- **Dependency Version Check**: Queries Maven Central to detect outdated `implementation`/`api` dependencies
- **Gradle Properties Check**: Detects missing build optimizations (parallel execution, build cache, configuration cache, JVM heap, VFS watching)
- **Multi-format Reports**: Generates `report.html`, `report.json` and `report.sarif` (SARIF 2.1.0 for GitHub Advanced Security)

## Installation

### Option 1: Using Gradle Plugin Portal

Add the plugin to your `settings.gradle` or `build.gradle`:

```groovy
// In settings.gradle
plugins {
    id 'com.davideagostini.analyzer' version '1.0.0'
}
```

### Option 2: Local Development

If the plugin is not yet published to the Gradle Plugin Portal, you can use Maven Local.

**Step 1: Build and publish the plugin locally**

```bash
# Clone the repository
git clone https://github.com/davideagostini/android-build-analyzer.git
cd android-build-analyzer

# Build and publish to Maven Local
./gradlew clean publishToMavenLocal
```

**Step 2: Add the plugin to your Android project**

In your Android project's `settings.gradle.kts`:

```kotlin
pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
}

plugins {
    id("com.davideagostini.analyzer") version "1.0.0"
}
```

Or if using Groovy `build.gradle`:

```groovy
// In settings.gradle
pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
}

plugins {
    id 'com.davideagostini.analyzer' version '1.0.0'
}
```

**Step 3: Configure the plugin**

Add the configuration block to your `app/build.gradle`:

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

**Step 4: Run the analysis**

```bash
./gradlew analyze
```

The HTML report will be generated at `app/build/reports/analyzer/report.html`.

**Note:** When using Maven Local, the plugin version must match the version in the plugin's `build.gradle.kts` (`version = "1.0.0"`).

## Configuration

The plugin provides configurable options via the `androidBuildAnalyzer` extension:

```groovy
androidBuildAnalyzer {
    enabled = true                    // Enable/disable the plugin
    apiKeyPatterns = [...]            // Custom regex patterns for API keys
    checkDebuggable = true           // Check for debuggable flag in release
    checkMinifyEnabled = true        // Check for minifyEnabled in release
    checkAllowBackup = true          // Check for allowBackup in manifest
    reportPath = "build/reports/analyzer"  // Output path for HTML report
    failOnCriticalIssues = false     // Fail build on HIGH severity issues (throws GradleException)
    excludePaths = []                // Path substrings to skip during scanning
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

## Usage

### Run Full Analysis

```bash
./gradlew analyze
```

This will run all analysis tasks and generate an HTML report.

### Run Individual Tasks

```bash
# Detect API keys
./gradlew detectApiKeys

# Analyze APK composition
./gradlew analyzeApk

# Run security checks
./gradlew securityCheck

# Analyze resources
./gradlew analyzeResources

# Generate HTML report
./gradlew generateAnalysisReport
```

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
| `report.json` | JSON | Scripting, dashboards, custom tooling |
| `report.sarif` | SARIF 2.1.0 | GitHub Advanced Security, IDE integration |

The HTML report includes summary cards, color-coded severity badges, and inline fix suggestions.

## Tasks

| Task | Description |
|------|-------------|
| `analyze` | Runs all analysis tasks and generates all reports |
| `detectApiKeys` | Scans source files for exposed API keys |
| `analyzeApk` | Analyzes APK composition — scans existing APK, does **not** trigger a build |
| `securityCheck` | Checks build config and manifest for security issues |
| `analyzeResources` | Analyzes resources for issues |
| `checkDependencyVersions` | Checks declared dependencies against Maven Central for updates |
| `checkGradleProperties` | Checks `gradle.properties` for missing build optimizations |
| `generateAnalysisReport` | Generates `report.html`, `report.json` and `report.sarif` |

## Publishing

### Maven Central

To publish to Maven Central, configure your publishing in `build.gradle.kts`:

```kotlin
publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.davideagostini"
            artifactId = "android-build-analyzer"
            version = "1.0.0"

            pom {
                name.set("Android Build Analyzer")
                description.set("Gradle plugin for Android security and performance analysis")
                url.set("https://github.com/davideagostini/android-build-analyzer")
            }
        }
    }
}
```

### GitHub Packages

You can also publish to GitHub Packages using the included CI workflow.

## Requirements

- Gradle 8.x
- Android Gradle Plugin 8.x
- Kotlin 1.9.x

## License

MIT License

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
