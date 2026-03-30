package io.github.davideagostini.analyzer.tasks

import io.github.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Resource issue types.
 */
enum class ResourceIssueType(val displayName: String) {
    UNUSED_RESOURCE("Unused Resource"),
    DUPLICATE_STRING("Duplicate String"),
    OVERSIZED_IMAGE("Oversized Image")
}

private data class ResourceKey(val type: String, val name: String)

/**
 * Task that analyzes Android resources.
 */
open class ResourceAnalysisTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> = project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:Internal
    val findings: MutableList<ResourceFinding> = mutableListOf()

    @TaskAction
    fun analyze() {
        findings.clear()

        if (!extension.get().enabled) {
            return
        }

        checkUnusedResources()
        checkDuplicateStrings()
        checkOversizedImages()

        applySuppressions()
        logFindings()
    }

    private fun checkUnusedResources() {
        val resDir = project.file("src/main/res")
        if (!resDir.exists()) return

        val declaredResources = parseDeclaredValueResources(resDir)
        if (declaredResources.isEmpty()) return

        val usedResources = mutableSetOf<ResourceKey>()
        usedResources += collectCodeResourceReferences()
        usedResources += collectXmlResourceReferences(resDir)
        usedResources += collectManifestResourceReferences()

        declaredResources
            .filterNot { it in usedResources }
            .forEach { unused ->
                findings.add(
                    ResourceFinding(
                        type = ResourceIssueType.UNUSED_RESOURCE,
                        severity = Severity.LOW,
                        resourceName = "${unused.type}/${unused.name}",
                        message = "Potentially unused resource '${unused.type}/${unused.name}' - not found in code or XML references",
                        location = "res/values/"
                    )
                )
            }
    }

    private fun parseDeclaredValueResources(resDir: File): Set<ResourceKey> {
        val declared = mutableSetOf<ResourceKey>()
        val valuesDirs = resDir.listFiles()?.filter { it.isDirectory && it.name.startsWith("values") } ?: emptyList()

        valuesDirs.forEach { valuesDir ->
            valuesDir.listFiles()?.filter { it.extension == "xml" }?.forEach valuesFileLoop@{ file ->
                try {
                    val factory = DocumentBuilderFactory.newInstance()
                    val builder = factory.newDocumentBuilder()
                    val doc = builder.parse(file)
                    val root = doc.documentElement ?: return@valuesFileLoop
                    val nodes = root.childNodes

                    for (i in 0 until nodes.length) {
                        val node = nodes.item(i)
                        if (node !is Element) continue

                        val name = node.getAttribute("name")?.trim().orEmpty()
                        if (name.isEmpty()) continue

                        val type = when (node.tagName) {
                            "item" -> node.getAttribute("type")?.trim().orEmpty()
                            else -> node.tagName
                        }

                        if (type.isNotEmpty()) {
                            declared.add(ResourceKey(type = type, name = name))
                        }
                    }
                } catch (_: Exception) {
                    // Skip files that can't be parsed
                }
            }
        }

        return declared
    }

    private fun applySuppressions() {
        val baselineEntries = FindingFilterSupport.loadBaseline(project, extension.get())
        val filtered = findings.filterNot { finding ->
            FindingFilterSupport.isSuppressed(
                ruleId = finding.type.name,
                fingerprint = FindingFilterSupport.sha256("${finding.type}:${finding.resourceName}:${finding.location}"),
                extension = extension.get(),
                baselineEntries = baselineEntries
            )
        }

        findings.clear()
        findings.addAll(filtered)
    }

    private fun collectCodeResourceReferences(): Set<ResourceKey> {
        val refs = mutableSetOf<ResourceKey>()
        val sourceFiles = project.fileTree("src/main") {
            include("**/*.java")
            include("**/*.kt")
        }

        val rRefPattern = Regex("""R\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)""")

        sourceFiles.forEach { file ->
            try {
                val content = file.readText()
                rRefPattern.findAll(content).forEach { match ->
                    refs.add(ResourceKey(type = match.groupValues[1], name = match.groupValues[2]))
                }
            } catch (_: Exception) {
                // Skip files that can't be read
            }
        }

        return refs
    }

    private fun collectXmlResourceReferences(resDir: File): Set<ResourceKey> {
        val refs = mutableSetOf<ResourceKey>()
        val xmlFiles = project.fileTree(resDir) { include("**/*.xml") }

        val refPattern = Regex("""@([A-Za-z0-9_]+)/([A-Za-z0-9_]+)""")

        xmlFiles.forEach { file ->
            try {
                val content = file.readText()
                refPattern.findAll(content).forEach { match ->
                    val type = match.groupValues[1]
                    val name = match.groupValues[2]
                    if (!type.startsWith("+")) {
                        refs.add(ResourceKey(type = type, name = name))
                    }
                }
            } catch (_: Exception) {
                // Skip files that can't be read
            }
        }

        return refs
    }

    private fun collectManifestResourceReferences(): Set<ResourceKey> {
        val manifestFile = project.file("src/main/AndroidManifest.xml")
        if (!manifestFile.exists()) return emptySet()

        val refs = mutableSetOf<ResourceKey>()
        val refPattern = Regex("""@([A-Za-z0-9_]+)/([A-Za-z0-9_]+)""")

        try {
            val content = manifestFile.readText()
            refPattern.findAll(content).forEach { match ->
                val type = match.groupValues[1]
                val name = match.groupValues[2]
                if (!type.startsWith("+")) {
                    refs.add(ResourceKey(type = type, name = name))
                }
            }
        } catch (_: Exception) {
            // Skip file if unreadable
        }

        return refs
    }

    private fun checkDuplicateStrings() {
        val stringsFile = project.file("src/main/res/values/strings.xml")
        if (!stringsFile.exists()) return

        try {
            val factory = DocumentBuilderFactory.newInstance()
            val builder = factory.newDocumentBuilder()
            val doc = builder.parse(stringsFile)

            val stringElements = doc.getElementsByTagName("string")
            val seenStrings = mutableMapOf<String, MutableList<String>>()

            for (i in 0 until stringElements.length) {
                val element = stringElements.item(i) as Element
                val name = element.getAttribute("name")
                if (name.isNotEmpty()) {
                    val value = element.textContent ?: ""
                    seenStrings.getOrPut(value) { mutableListOf() }.add(name)
                }
            }

            seenStrings.filter { it.value.size > 1 }.forEach { (value, names) ->
                findings.add(
                    ResourceFinding(
                        type = ResourceIssueType.DUPLICATE_STRING,
                        severity = Severity.LOW,
                        resourceName = names.joinToString(", "),
                        message = "Duplicate string value: \"$value\"",
                        location = "res/values/strings.xml"
                    )
                )
            }
        } catch (e: Exception) {
            logger.warn("Could not parse strings.xml: ${e.message}")
        }
    }

    private fun checkOversizedImages() {
        val drawableDirs = listOf(
            "src/main/res/drawable",
            "src/main/res/drawable-hdpi",
            "src/main/res/drawable-xhdpi",
            "src/main/res/drawable-xxhdpi",
            "src/main/res/mipmap-hdpi",
            "src/main/res/mipmap-xhdpi",
            "src/main/res/mipmap-xxhdpi"
        )

        // Also check assets folder for oversized images
        val assetsDir = project.file("src/main/assets")

        val maxSizeBytes = 1024L * 1024L

        drawableDirs.forEach { dirPath ->
            val dir = project.file(dirPath)
            if (dir.exists()) {
                dir.listFiles()?.filter {
                    it.extension in listOf("png", "jpg", "jpeg", "webp")
                }?.filter { it.length() > maxSizeBytes }?.forEach { file ->
                    findings.add(
                        ResourceFinding(
                            type = ResourceIssueType.OVERSIZED_IMAGE,
                            severity = Severity.MEDIUM,
                            resourceName = file.name,
                            message = "Image file exceeds 1MB (${formatSize(file.length())})",
                            location = file.relativeTo(project.rootDir).path
                        )
                    )
                }
            }
        }

        // Check assets folder for oversized image files
        if (assetsDir.exists()) {
            assetsDir.walkTopDown().filter {
                it.extension in listOf("png", "jpg", "jpeg", "webp", "gif")
            }.filter { it.length() > maxSizeBytes }.forEach { file ->
                findings.add(
                    ResourceFinding(
                        type = ResourceIssueType.OVERSIZED_IMAGE,
                        severity = Severity.MEDIUM,
                        resourceName = file.name,
                        message = "Image file exceeds 1MB (${formatSize(file.length())})",
                        location = file.relativeTo(project.rootDir).path
                    )
                )
            }
        }
    }

    private fun formatSize(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.2f MB", bytes / (1024.0 * 1024.0))
            bytes >= 1024 -> String.format("%.2f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
    }

    private fun logFindings() {
        logger.quiet("=".repeat(50))
        logger.quiet("Resource Analysis Results")
        logger.quiet("=".repeat(50))

        if (findings.isEmpty()) {
            logger.quiet("No resource issues found.")
        } else {
            logger.quiet("Found ${findings.size} resource issue(s):")

            findings.forEach { finding ->
                val colorCode = when (finding.severity) {
                    Severity.HIGH -> "\u001B[31m"
                    Severity.MEDIUM -> "\u001B[33m"
                    Severity.LOW -> "\u001B[32m"
                }
                val reset = "\u001B[0m"

                logger.quiet("$colorCode${finding.severity.name}$reset: ${finding.type.displayName}")
                logger.quiet("   ${finding.message}")
                logger.quiet("   Resource: ${finding.resourceName}")
            }
        }
    }
}

data class ResourceFinding(
    val type: ResourceIssueType,
    val severity: Severity,
    val resourceName: String,
    val message: String,
    val location: String
)
