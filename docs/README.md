# Android Build Analyzer Plugin

A Gradle plugin for Android security and performance analysis. This plugin provides automated checks for API key exposure, APK composition, security vulnerabilities, and resource optimization.

## Overview

The Android Build Analyzer plugin scans your Android project to identify:
- **API Key Exposure**: Detects hardcoded API keys in source code
- **APK Analysis**: Shows APK composition and size breakdown
- **Security Checks**: Identifies common security vulnerabilities
- **Resource Analysis**: Finds duplicate strings, unused resources, and oversized images

## Requirements

- Android Gradle Plugin 8.2.2
- Kotlin 1.9.22
- Java 17
- Gradle 8.2+

## Quick Start

### 1. Apply the Plugin

Add the plugin to your Android app's `build.gradle.kts`:

```kotlin
plugins {
    id("com.android.application")
    id("com.davideagostini.analyzer")
}
```

Or for a library module:

```kotlin
plugins {
    id("com.android.library")
    id("com.davideagostini.analyzer")
}
```

### 2. Configure (Optional)

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

### 3. Run Analysis

```bash
./gradlew analyze
```

This will:
1. Build the debug and release APKs
2. Run all analysis tasks
3. Generate an HTML report

## Architecture

### Core Classes

#### 1. AndroidBuildAnalyzerPlugin

**File**: `src/main/kotlin/com/davideagostini/analyzer/AndroidBuildAnalyzerPlugin.kt`

The main plugin class that registers all tasks and extensions.

**Key Responsibilities**:
- Registers the `androidBuildAnalyzer` extension
- Creates all analysis tasks (`detectApiKeys`, `analyzeApk`, `securityCheck`, `analyzeResources`, `generateAnalysisReport`)
- Creates the main `analyze` task that orchestrates all analysis
- Validates that the project has Android plugin applied

**Key Methods**:
- `apply(project: Project)`: Main entry point, registers all tasks and extension
- `isAndroidProject(project: Project)`: Checks if project has Android application or library plugin

**Tasks Created**:
| Task | Description |
|------|-------------|
| `detectApiKeys` | Scans source files for API keys |
| `analyzeApk` | Analyzes APK composition |
| `securityCheck` | Checks for security issues |
| `analyzeResources` | Analyzes Android resources |
| `generateAnalysisReport` | Generates HTML report |
| `analyze` | Main task that runs all analysis |

---

#### 2. AndroidBuildAnalyzerExtension

**File**: `src/main/kotlin/com/davideagostini/analyzer/AndroidBuildAnalyzerExtension.kt`

Configuration class for the plugin.

**Properties**:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | Boolean | true | Enable/disable the analyzer |
| `apiKeyPatterns` | List<String> | defaultApiKeyPatterns | Regex patterns for API key detection |
| `srcDirs` | FileCollection | src/main/java, src/main/kotlin, src/main/res, src/debug, src/release | Source directories to scan |
| `checkDebuggable` | Boolean | true | Check for debuggable=true in release |
| `checkMinifyEnabled` | Boolean | true | Check for minifyEnabled=true in release |
| `checkAllowBackup` | Boolean | true | Check for allowBackup in manifest |
| `reportPath` | String | build/reports/analyzer | Path for HTML report |
| `failOnCriticalIssues` | Boolean | false | Fail build on critical issues |

**Default API Key Patterns**:
```kotlin
val defaultApiKeyPatterns = listOf(
    "(AKIA|ASIA)[A-Z0-9]{16}",           // AWS keys
    "AIza[0-9A-Za-z\\-_]{35}",           // Firebase
    "[aA][pP][iI][-_]?[kK][eE][yY].*['\"][a-zA-Z0-9]{20,}['\"]",  // Generic API key
    "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",  // Private keys
    "[sS][tT][rR][iI][pP][eE][_]?[pP][uU][bB][lL][iI][cC][_]?[kK][eE][yY].*['\"][a-zA-Z0-9]{20,}['\"]",  // Stripe
    "[gG][oO][oO][gG][lL][eE][_]?[aA][pP][iI][_]?[kK][eE][yY].*['\"][a-zA-Z0-9]{20,}['\"]"  // Google API key
)
```

---

### Analysis Tasks

#### 3. ApiKeyDetectionTask

**File**: `src/main/kotlin/com/davideagostini/analyzer/tasks/ApiKeyDetectionTask.kt`

Scans source files for exposed API keys.

**Key Features**:
- Scans Java, Kotlin, XML, and Gradle files
- Uses configurable regex patterns
- Masks sensitive data in output
- Assigns severity based on key type

**Properties**:
| Property | Type | Description |
|----------|------|-------------|
| `extension` | Property<AndroidBuildAnalyzerExtension> | Configuration |
| `patterns` | List<String> | Custom patterns (overrides extension) |
| `findings` | MutableList<ApiKeyFinding> | Detected API keys |

**Data Class - ApiKeyFinding**:
```kotlin
data class ApiKeyFinding(
    val file: String,        // File path
    val line: Int,           // Line number
    val pattern: String,     // Regex pattern matched
    val matched: String,     // Masked matched text
    val severity: Severity   // HIGH, MEDIUM, LOW
)
```

**Severity Logic**:
- `HIGH`: Private keys, AWS keys (AKIA/ASIA), Firebase keys, Stripe keys
- `MEDIUM`: Generic API keys
- `LOW`: (Reserved for future use)

**Improvement Ideas**:
- Add support for more key types (Twilio, SendGrid, etc.)
- Add suppression annotations (@SuppressWarnings("ApiKey"))
- Add ignore list for false positives
- Add support for .env files

---

#### 4. ApkAnalysisTask

**File**: `src/main/kotlin/com/davideagostini/analyzer/tasks/ApkAnalysisTask.kt`

Analyzes APK composition and size breakdown.

**Key Features**:
- Uses Java ZipFile API to analyze APK
- Categorizes APK entries by type
- Calculates percentage breakdown
- Supports both debug and release APKs

**Properties**:
| Property | Type | Description |
|----------|------|-------------|
| `extension` | Property<AndroidBuildAnalyzerExtension> | Configuration |
| `apkComponents` | MutableList<ApkComponent> | Analysis results |

**Data Class - ApkComponent**:
```kotlin
data class ApkComponent(
    val name: String,        // Component name
    val size: Long,          // Size in bytes
    val percentage: Double   // Percentage of total
)
```

**Categories**:
| Category | Description |
|----------|-------------|
| DEX (Bytecode) | Dalvik/ART bytecode |
| Resources Table | resources.arsc |
| Native Libraries | lib/ directory |
| Android Resources | res/ directory |
| Assets | assets/ directory |
| META-INF | Signing files |
| XML Files | Binary XML files |
| Other | Everything else |

**APK Search Locations**:
- `build/outputs/apk/debug/`
- `build/outputs/apk/release/`

**Improvement Ideas**:
- Add per-DEX method count analysis
- Add DEX compression analysis
- Add native library ABI breakdown
- Add comparison with previous build

---

#### 5. SecurityCheckTask

**File**: `src/main/kotlin/com/davideagostini/analyzer/tasks/SecurityCheckTask.kt`

Checks for security vulnerabilities in build configuration and manifest.

**Key Features**:
- Analyzes build.gradle for security settings
- Analyzes AndroidManifest.xml for security issues
- Configurable checks via extension

**Issue Types - SecurityIssueType**:
```kotlin
enum class SecurityIssueType(val displayName: String) {
    DEBUG_ENABLED("Debug Enabled in Release"),
    PROGUARD_DISABLED("ProGuard/R8 Disabled"),
    DEBUG_APP_ID("Debug Application ID"),
    MANIFEST_DEBUGGABLE("Manifest Debuggable Flag"),
    ALLOW_BACKUP_ENABLED("Backup Enabled"),
    CLEARTEXT_TRAFFIC("Cleartext Traffic Allowed"),
    EXPORTED_COMPONENT("Exported Component Without Permission")
}
```

**Data Class - SecurityFinding**:
```kotlin
data class SecurityFinding(
    val type: SecurityIssueType,
    val severity: Severity,
    val message: String,
    val location: String,
    val buildType: String  // "release", "debug", "all"
)
```

**Checks Performed**:

1. **Build Configuration**:
   - `debuggable=true` in release build type (HIGH)
   - `minifyEnabled=false` in release build type (HIGH)
   - Application ID contains `.debug` or `.test` (MEDIUM)

2. **Manifest Analysis**:
   - `android:debuggable="true"` (HIGH)
   - `android:allowBackup="true"` (MEDIUM) - if checkAllowBackup enabled
   - `android:usesCleartextTraffic="true"` (MEDIUM)
   - Exported components without permission (LOW)

**Improvement Ideas**:
- Add check for weak signature algorithms
- Add check for insecure network security config
- Add check for debuggable components
- Add check for intent filter vulnerabilities

---

#### 6. ResourceAnalysisTask

**File**: `src/main/kotlin/com/davideagostini/analyzer/tasks/ResourceAnalysisTask.kt`

Analyzes Android resources for optimization opportunities.

**Issue Types - ResourceIssueType**:
```kotlin
enum class ResourceIssueType(val displayName: String) {
    UNUSED_RESOURCE("Unused Resource"),
    DUPLICATE_STRING("Duplicate String"),
    OVERSIZED_IMAGE("Oversized Image")
}
```

**Data Class - ResourceFinding**:
```kotlin
data class ResourceFinding(
    val type: ResourceIssueType,
    val severity: Severity,
    val resourceName: String,
    val message: String,
    val location: String
)
```

**Checks Performed**:

1. **Unused Resources**:
   - Parses XML resource files
   - Scans source code for R.* references
   - Reports resources not referenced in code (LOW)

2. **Duplicate Strings**:
   - Parses strings.xml
   - Groups by string value
   - Reports duplicates (LOW)

3. **Oversized Images**:
   - Scans drawable and mipmap directories
   - Checks PNG, JPG, JPEG, WebP files
   - Reports files > 1MB (MEDIUM)

**Improvement Ideas**:
- Add vector drawable analysis
- Add density-specific resource analysis
- Add string translation analysis
- Add color resource analysis

---

#### 7. ReportGeneratorTask

**File**: `src/main/kotlin/com/davideagostini/analyzer/tasks/ReportGeneratorTask.kt`

Generates an HTML report combining all analysis results.

**Properties**:
| Property | Type | Description |
|----------|------|-------------|
| `extension` | Property<AndroidBuildAnalyzerExtension> | Configuration |
| `reportDir` | File | Output directory |
| `apiKeyTask` | Property<ApiKeyDetectionTask> | API key results |
| `apkAnalysisTask` | Property<ApkAnalysisTask> | APK analysis results |
| `securityCheckTask` | Property<SecurityCheckTask> | Security results |
| `resourceAnalysisTask` | Property<ResourceAnalysisTask> | Resource results |

**Report Features**:
- Summary cards with counts
- Color-coded severity badges
- Detailed tables for each category
- Responsive design
- Timestamp generation

**Output**: `build/reports/analyzer/report.html`

**Improvement Ideas**:
- Add JSON/XML export option
- Add trend analysis over builds
- Add export to CSV
- Add integration with CI/CD

---

### Shared Data Classes

#### Severity Enum

**File**: Defined in ApiKeyDetectionTask.kt

```kotlin
enum class Severity {
    HIGH,    // Critical issues requiring immediate attention
    MEDIUM,  // Issues that should be addressed
    LOW      // Minor issues or recommendations
}
```

---

## Extension Points for Future Improvements

### Adding New Analysis Tasks

1. Create a new task class extending `DefaultTask`
2. Add `@get:Internal` for extension property
3. Add findings list property
4. Implement `@TaskAction` method
5. Register task in `AndroidBuildAnalyzerPlugin.apply()`
6. Add task dependency to `generateAnalysisReport`

### Adding New Configuration Options

1. Add property to `AndroidBuildAnalyzerExtension`
2. Add `@get:Input` annotation for task caching
3. Update plugin to pass configuration to tasks

### Adding New Report Sections

1. Add task reference to `ReportGeneratorTask`
2. Add data class for findings
3. Implement build method in `ReportGeneratorTask`
4. Add section to HTML template

---

## Known Limitations

1. **API Key Detection**: Uses regex patterns - may have false positives/negatives
2. **Unused Resources**: Basic R. reference check - may not detect dynamic references
3. **APK Analysis**: Only analyzes first APK found
4. **Manifest Parsing**: Uses regex rather than XML parsing

---

## Testing

A test app is included in `test-app/` that demonstrates all plugin features:
- Fake API keys for detection
- Debug build config for security checks
- Duplicate strings for resource analysis

Run tests:
```bash
cd test-app
./gradlew analyze
```

---

## Version History

- **1.0.0**: Initial release with API key detection, APK analysis, security checks, and resource analysis
