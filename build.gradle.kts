plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    id("com.gradle.plugin-publish") version "2.0.0"
}

group = "com.davideagostini"
version = "1.0.0"

repositories {
    google()
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.24")
    implementation("com.android.tools.build:gradle:8.2.2")
    implementation(gradleApi())
    implementation(localGroovy())
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
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
            tags.set(listOf("android", "security", "performance", "analyzer"))
        }
    }
}

gradlePlugin {
    website.set("https://github.com/davideagostini/android-build-analyzer")
    vcsUrl.set("https://github.com/davideagostini/android-build-analyzer")
}
