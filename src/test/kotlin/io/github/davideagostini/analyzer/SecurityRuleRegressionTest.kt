package io.github.davideagostini.analyzer

import io.github.davideagostini.analyzer.tasks.SecurityCheckTask
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SecurityRuleRegressionTest {

    @Test
    fun appIdDetectionFlagsOnlyDedicatedDebugOrTestSegments() {
        assertFalse(SecurityCheckTask.isSuspiciousAppId("com.example.testapp"))
        assertFalse(SecurityCheckTask.isSuspiciousAppId("com.company.production"))

        assertTrue(SecurityCheckTask.isSuspiciousAppId("com.mycompany.myapp.debug"))
        assertTrue(SecurityCheckTask.isSuspiciousAppId("com.mycompany.myapp.test"))
        assertTrue(SecurityCheckTask.isSuspiciousAppId("com.test.mycompany.app"))
    }

    @Test
    fun appIdAllowlistSuppressesFlaggedApplicationIds() {
        assertFalse(
            SecurityCheckTask.shouldFlagApplicationId(
                "com.example.myapp.debug",
                listOf("com.example.")
            )
        )
        assertTrue(
            SecurityCheckTask.shouldFlagApplicationId(
                "com.production.myapp.debug",
                listOf("com.example.")
            )
        )
    }

    @Test
    fun undeclaredCustomPermissionsAreDetected() {
        val manifest = """
            <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-permission android:name="com.example.app.permission.SYNC" />
                <uses-permission android:name="android.permission.INTERNET" />
            </manifest>
        """.trimIndent()

        val result = SecurityCheckTask.findUndeclaredCustomPermissions(manifest)

        assertEquals(setOf("com.example.app.permission.SYNC"), result)
    }

    @Test
    fun declaredCustomPermissionsAreNotDetectedAsUndefined() {
        val manifest = """
            <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
                <permission android:name="com.example.app.permission.SYNC" />
                <uses-permission android:name="com.example.app.permission.SYNC" />
            </manifest>
        """.trimIndent()

        val result = SecurityCheckTask.findUndeclaredCustomPermissions(manifest)

        assertTrue(result.isEmpty())
    }

    @Test
    fun exportedActivityWithoutPermissionIsDetectedOnce() {
        val manifest = """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <activity android:name=".NoPermissionActivity" android:exported="true" />
                    <activity
                        android:name=".ProtectedActivity"
                        android:exported="true"
                        android:permission="com.example.permission.PROTECTED" />
                </application>
            </manifest>
        """.trimIndent()

        val result = SecurityCheckTask.findExportedActivitiesWithoutPermission(manifest)

        assertEquals(listOf(".NoPermissionActivity"), result)
    }

    @Test
    fun insecureHttpSuggestionReplacesOnlyTheLeadingScheme() {
        assertEquals(
            "https://http.example.com",
            SecurityCheckTask.suggestHttpsUrl("http://http://http.example.com")
        )
    }
}
