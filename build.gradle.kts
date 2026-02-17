plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    `maven-publish`
    signing
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

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = group.toString()
            artifactId = "android-build-analyzer"
            version = version.toString()

            artifact(tasks.named("jar"))

            pom {
                name.set("Android Build Analyzer")
                description.set("Gradle plugin for Android security and performance analysis")
                url.set("https://github.com/davideagostini/android-build-analyzer")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("davideagostini")
                        name.set("Davide Agostini")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/davideagostini/android-build-analyzer.git")
                    developerConnection.set("scm:git:git@github.com:davideagostini/android-build-analyzer.git")
                    url.set("https://github.com/davideagostini/android-build-analyzer")
                }
            }
        }
    }
}

signing {
    sign(publishing.publications["maven"])
}
