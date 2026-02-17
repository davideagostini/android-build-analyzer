# Android Build Analyzer Plugin

A Gradle plugin for Android developers to detect security issues and analyze APK performance.

## Features

- **API Key Detection**: Scans source files for exposed API keys (AWS, Firebase, generic API keys, private keys, Stripe, Google)
- **APK Composition Analysis**: Breaks down APK size by component (DEX, resources, assets, native libraries)
- **Security Best Practices**: Checks for debug flags, ProGuard/R8, allowBackup, cleartext traffic
- **Resource Analysis**: Finds unused resources, duplicate strings, oversized images
- **HTML Report**: Generates a comprehensive HTML report with color-coded severity levels

## Installation

### Option 1: Using Gradle Plugin Portal

Add the plugin to your `settings.gradle` or `build.gradle`:

```groovy
// In settings.gradle
plugins {
    id 'com.davideagostini.analyzer' version '1.0.0'
}
```

### Option 2: Using JitPack

If the plugin is published to JitPack, add this to your `settings.gradle`:

```groovy
pluginManagement {
    repositories {
        maven { url 'https://jitpack.io' }
        gradlePluginPortal()
    }
}

plugins {
    id 'com.davideagostini.analyzer' version '1.0.0'
}
```

### Option 3: Local Development

To test locally without publishing:

```groovy
// In build.gradle (project level)
buildscript {
    repositories {
        mavenLocal()
    }
    dependencies {
        classpath 'com.davideagostini:android-build-analyzer:1.0.0'
    }
}

// In build.gradle (app level)
apply plugin: 'com.davideagostini.analyzer'
```

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
    failOnCriticalIssues = false     // Fail build on critical issues
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

### HTML Report

The HTML report is generated at: `build/reports/analyzer/report.html`

The report includes:
- Summary cards showing counts
- API Key Detection section
- Security Checks section
- Resource Analysis section
- Color-coded severity badges

## Tasks

| Task | Description |
|------|-------------|
| `analyze` | Runs all analysis tasks and generates report |
| `detectApiKeys` | Scans source files for exposed API keys |
| `analyzeApk` | Analyzes APK composition (requires APK to exist) |
| `securityCheck` | Checks build config and manifest for security issues |
| `analyzeResources` | Analyzes resources for issues |
| `generateAnalysisReport` | Generates HTML report |

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
