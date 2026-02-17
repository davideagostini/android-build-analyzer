# Android Build Analyzer Plugin

A Gradle plugin for Android security and performance analysis. This plugin provides automated checks for API key exposure, APK composition analysis, security vulnerabilities detection, and resource optimization.

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

**Checks:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Debug Enabled in Release | HIGH | debuggable=true in release build |
| ProGuard/R8 Disabled | HIGH | minifyEnabled=false in release |
| Debug App ID | MEDIUM | Application ID contains .debug or .test |
| Manifest Debuggable | HIGH | android:debuggable="true" in manifest |
| Allow Backup | MEDIUM | android:allowBackup="true" |
| Cleartext Traffic | MEDIUM | android:usesCleartextTraffic="true" |
| Exported Component | LOW | Exported without permission |

### 4. Resource Analysis
Optimizes your app's resources to reduce APK size.

**Checks:**
- **Unused Resources**: Finds resources not referenced in code
- **Duplicate Strings**: Identifies duplicate string values
- **Oversized Images**: Flags images larger than 1MB

### 5. HTML Report
Generates a comprehensive HTML report with:
- Summary cards with issue counts
- Color-coded severity badges
- Detailed findings for each category
- Responsive design

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
    id("com.davideagostini.analyzer") version "1.0.0"
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
    failOnCriticalIssues = false  // Fail build on HIGH severity issues

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
1. Build debug and release APKs
2. Run all analysis tasks
3. Generate HTML report

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
| `failOnCriticalIssues` | Boolean | false | Fail build on HIGH issues |
| `apiKeyPatterns` | List<String> | (default patterns) | Custom detection patterns |
| `srcDirs` | FileCollection | src/main/* | Directories to scan |

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

Add to your source code to suppress warnings:

```kotlin
// The analyzer uses regex patterns, not annotations
// Currently no suppression mechanism - use custom patterns to exclude
```

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
    id("com.davideagostini.analyzer")
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

#### 4. ProGuard/R8 Analysis
- **Rules quality check**: Validate ProGuard rules
- **Missing rules warning**: Suggest rules for common libraries
- **Optimization suggestions**: Recommend R8 optimizations

#### 5. Network Security
- **Network Security Config**: Analyze security configuration
- **HTTP URL detection**: Find cleartext HTTP URLs in code
- **Certificate pinning**: Check for certificate pinning implementation

#### 6. Enhanced Manifest Analysis
- **Permission analysis**: Review permission usage
- **Component security**: Detailed exported component analysis
- **Intent filter security**: Check for intent filter vulnerabilities

#### 7. CI/CD Integration
- **JSON/XML export**: Machine-readable report formats
- **GitHub Security Alerts**: Integration with GitHub security tab
- **Trend analysis**: Track issues across builds
- **Slack/Teams notifications**: Alert on critical issues

#### 8. Custom Rules Engine
- **User-defined patterns**: Allow custom regex rules
- **Rule categories**: Organize custom rules by type
- **Rule sharing**: Share rule sets between projects

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
