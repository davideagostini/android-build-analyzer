plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    id("com.gradle.plugin-publish") version "1.2.1"
}

group = "com.davideagostini"
version = "1.0.0"

repositories {
    google()
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.22")
    implementation("com.android.tools.build:gradle:8.2.2")
    implementation(gradleApi())
    implementation(localGroovy())
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "17"
    }
}

tasks.withType<ProcessResources>().configureEach {
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
}

gradlePlugin {
    plugins {
        create("androidBuildAnalyzer") {
            id = "com.davideagostini.analyzer"
            displayName = "Android Build Analyzer"
            description = "Gradle plugin for Android security and performance analysis"
            implementationClass = "com.davideagostini.analyzer.AndroidBuildAnalyzerPlugin"
        }
    }
}
