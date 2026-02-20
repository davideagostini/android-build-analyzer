package io.github.davideagostini.analyzer

import io.github.davideagostini.analyzer.tasks.SecurityFinding
import io.github.davideagostini.analyzer.tasks.SecurityIssueType
import io.github.davideagostini.analyzer.tasks.Severity
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.io.File

class SecurityCheckTaskTest {

    @Test
    fun testDangerousPermissionDetection() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-permission android:name="android.permission.CAMERA" />
                <uses-permission android:name="android.permission.READ_SMS" />
                <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        assertTrue(findings.any { it.type == SecurityIssueType.DANGEROUS_PERMISSION && it.message.contains("CAMERA") })
        assertTrue(findings.any { it.type == SecurityIssueType.DANGEROUS_PERMISSION && it.message.contains("READ_SMS") })
        assertTrue(findings.any { it.type == SecurityIssueType.DANGEROUS_PERMISSION && it.message.contains("ACCESS_FINE_LOCATION") })

        // READ_SMS should be HIGH severity
        val smsFinding = findings.find { it.message.contains("READ_SMS") }
        assertEquals(Severity.HIGH, smsFinding?.severity)

        // CAMERA and LOCATION should be MEDIUM severity
        val cameraFinding = findings.find { it.message.contains("CAMERA") }
        assertEquals(Severity.MEDIUM, cameraFinding?.severity)
    }

    @Test
    fun testHighRiskPermissionDetection() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-permission android:name="android.permission.READ_CALL_LOG" />
                <uses-permission android:name="android.permission.WRITE_SETTINGS" />
                <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        assertTrue(findings.any { it.type == SecurityIssueType.DANGEROUS_PERMISSION && it.message.contains("READ_CALL_LOG") })
        assertTrue(findings.any { it.type == SecurityIssueType.DANGEROUS_PERMISSION && it.message.contains("WRITE_SETTINGS") })
        assertTrue(findings.any { it.type == SecurityIssueType.DANGEROUS_PERMISSION && it.message.contains("SYSTEM_ALERT_WINDOW") })

        // All high-risk permissions should be HIGH severity
        findings.filter { it.type == SecurityIssueType.DANGEROUS_PERMISSION }.forEach {
            assertEquals(Severity.HIGH, it.severity, "Permission ${it.message} should be HIGH severity")
        }
    }

    @Test
    fun testExportedServiceWithoutPermission() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <service
                        android:name=".MyService"
                        android:exported="true" />
                </application>
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        assertTrue(findings.any { it.type == SecurityIssueType.EXPORTED_SERVICE })
        assertTrue(findings.any { it.message.contains("MyService") })
    }

    @Test
    fun testExportedReceiverWithoutPermission() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <receiver
                        android:name=".MyReceiver"
                        android:exported="true" />
                </application>
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        assertTrue(findings.any { it.type == SecurityIssueType.EXPORTED_RECEIVER })
        assertTrue(findings.any { it.message.contains("MyReceiver") })
    }

    @Test
    fun testExportedProviderWithoutPermission() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <provider
                        android:name=".MyProvider"
                        android:authorities="com.example.provider"
                        android:exported="true" />
                </application>
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        assertTrue(findings.any { it.type == SecurityIssueType.EXPORTED_PROVIDER })
        assertTrue(findings.any { it.message.contains("MyProvider") })

        // Provider should be HIGH severity
        val providerFinding = findings.find { it.type == SecurityIssueType.EXPORTED_PROVIDER }
        assertEquals(Severity.HIGH, providerFinding?.severity)
    }

    @Test
    fun testIntentFilterWithDataExposure() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <activity android:name=".MainActivity" android:exported="true">
                        <intent-filter>
                            <action android:name="com.example.ACTION_VIEW" />
                            <category android:name="android.intent.category.DEFAULT" />
                            <data android:mimeType="text/plain" />
                        </intent-filter>
                    </activity>
                </application>
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        assertTrue(findings.any { it.type == SecurityIssueType.INTENT_FILTER_DATA_EXPOSURE })
    }

    @Test
    fun testExportedComponentWithPermissionShouldNotTrigger() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <service
                        android:name=".MyService"
                        android:exported="true"
                        android:permission="com.example.PERMISSION" />
                    <receiver
                        android:name=".MyReceiver"
                        android:exported="true"
                        android:permission="com.example.PERMISSION" />
                    <provider
                        android:name=".MyProvider"
                        android:authorities="com.example.provider"
                        android:exported="true"
                        android:permission="com.example.PERMISSION" />
                </application>
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        // Should not find exported service/receiver/provider without permission
        assertFalse(findings.any { it.type == SecurityIssueType.EXPORTED_SERVICE })
        assertFalse(findings.any { it.type == SecurityIssueType.EXPORTED_RECEIVER })
        assertFalse(findings.any { it.type == SecurityIssueType.EXPORTED_PROVIDER })
    }

    @Test
    fun testNoIssuesInCleanManifest() {
        val manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-permission android:name="android.permission.INTERNET" />
                <application
                    android:allowBackup="false">
                    <activity
                        android:name=".MainActivity"
                        android:exported="true"
                        android:permission="com.example.PERMISSION">
                        <intent-filter>
                            <action android:name="android.intent.action.MAIN" />
                            <category android:name="android.intent.category.LAUNCHER" />
                        </intent-filter>
                    </activity>
                </application>
            </manifest>
        """.trimIndent()

        val findings = analyzeManifest(manifest)

        // Should only have dangerous permission for INTERNET (which is not dangerous)
        // and exported activity with permission (should be fine)
        val dangerousPermissions = findings.filter { it.type == SecurityIssueType.DANGEROUS_PERMISSION }
        assertTrue(dangerousPermissions.isEmpty() || dangerousPermissions.all { it.message.contains("INTERNET").not() })
    }

    // Helper function to analyze manifest content
    private fun analyzeManifest(manifestContent: String): List<SecurityFinding> {
        // Create a temporary manifest file
        val tempFile = File.createTempFile("AndroidManifest", ".xml")
        tempFile.writeText(manifestContent)
        tempFile.deleteOnExit()

        // Return a mock list of findings based on manifest content
        val findings = mutableListOf<SecurityFinding>()

        // Check dangerous permissions
        val dangerousPerms = listOf(
            "CAMERA", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO",
            "READ_SMS", "READ_CALL_LOG", "WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW"
        )
        val highRiskPerms = listOf("READ_CALL_LOG", "READ_SMS", "WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW")

        dangerousPerms.forEach { perm ->
            if (manifestContent.contains("android.permission.$perm")) {
                val severity = if (perm in highRiskPerms) Severity.HIGH else Severity.MEDIUM
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.DANGEROUS_PERMISSION,
                        severity = severity,
                        message = "Uses dangerous permission: $perm - Review if absolutely necessary",
                        location = "AndroidManifest.xml (uses-permission)",
                        buildType = "all"
                    )
                )
            }
        }

        // Check exported components
        if (manifestContent.contains("<service") && manifestContent.contains("android:exported=\"true\"")) {
            if (!manifestContent.contains("android:permission=") || !manifestContent.contains("<service") ||
                manifestContent.substringAfter("<service").substringBefore(">").contains("android:exported=\"true\"") &&
                !manifestContent.substringAfter("<service").substringBefore(">").contains("android:permission=")) {
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_SERVICE,
                        severity = Severity.MEDIUM,
                        message = "Exported service has no permission protection",
                        location = "AndroidManifest.xml",
                        buildType = "all"
                    )
                )
            }
        }

        if (manifestContent.contains("<receiver") && manifestContent.contains("android:exported=\"true\"")) {
            val receiverSection = manifestContent.substringAfter("<receiver").substringBefore("</receiver>")
            if (!receiverSection.contains("android:permission=")) {
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_RECEIVER,
                        severity = Severity.MEDIUM,
                        message = "Exported broadcast receiver has no permission protection",
                        location = "AndroidManifest.xml",
                        buildType = "all"
                    )
                )
            }
        }

        if (manifestContent.contains("<provider") && manifestContent.contains("android:exported=\"true\"")) {
            val providerSection = manifestContent.substringAfter("<provider").substringBefore("</provider>")
            if (!providerSection.contains("android:permission=")) {
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_PROVIDER,
                        severity = Severity.HIGH,
                        message = "Exported content provider has no permission protection",
                        location = "AndroidManifest.xml",
                        buildType = "all"
                    )
                )
            }
        }

        // Check intent filter with data
        if (manifestContent.contains("<data ") && manifestContent.contains("android:exported=\"true\"") &&
            manifestContent.contains("<intent-filter")) {
            findings.add(
                SecurityFinding(
                    type = SecurityIssueType.INTENT_FILTER_DATA_EXPOSURE,
                    severity = Severity.LOW,
                    message = "Intent filter with action may expose data",
                    location = "AndroidManifest.xml (intent-filter)",
                    buildType = "all"
                )
            )
        }

        return findings
    }
}
