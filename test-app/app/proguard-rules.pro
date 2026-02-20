# ProGuard rules for Test App
# Add project specific ProGuard rules here.

# Keep line numbers for debugging
-keepattributes SourceFile,LineNumberTable

# Keep custom view classes
-keep class com.example.testapp.** { *; }

# OkHttp rules (incomplete - should trigger warning)
-dontwarn okhttp3.**
-dontwarn okio.**

# Note: Missing -keepclassmembers rules (will trigger warning)
