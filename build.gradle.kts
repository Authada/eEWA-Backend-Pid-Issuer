import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Locale

plugins {
    base
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.wsdl2java)
}

buildscript {
    dependencies {
        classpath("org.glassfish.jaxb:jaxb-runtime:4.0.5")

    }
}
repositories {
    mavenCentral()
    maven {
        url = uri("https://jitpack.io")
    }
    maven {
        url = uri("https://repo.danubetech.com/repository/maven-public")
    }
    maven {
        url = uri("https://build.shibboleth.net/nexus/content/repositories/releases/")
    }
    maven("https://maven.waltid.dev/releases")
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server") {
        because("PID Issuer acts like a OAUTH2 resource server")
    }
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf") {
        because("For HTML templates")
    }
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.arrow.core) {
        because("Functional programming support")
    }
    implementation(libs.presentation.exchange)
    implementation(libs.arrow.fx.coroutines)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.eudi.sdjwt) {
        because("To Support issuance in SD-JWT-VC format")
    }
    implementation(libs.bouncy.castle) {
        because("To support X509 certificates parsing")
    }
    implementation("org.webjars:webjars-locator-core") {
        because("To support resolution of Webjars static resources")
    }
    implementation(libs.bootstrap) {
        because("For inclusion in HTML templates")
    }
    implementation(libs.qrgen) {
        because("To generate a QR Code for Credentials Offer URI")
    }
    implementation(libs.did.common) {
        because("To support parsing of DID URLs")
    }
    implementation(libs.multiformat) {
        because("To support resolution of did:key")
    }
    implementation(libs.result.monad) {
        because("Optional dependency from org.erwinkok.multiformat:multiformat that we require")
    }
    implementation(libs.nimbus.oauth2) {
        because("To support DPoP")
    }
    implementation(libs.keycloak.admin.client) {
        because("To be able to fetch user attributes")
    }
    implementation(libs.waltid.mdoc.credentials) {
        because("To sign CBOR credentials")
    }
    implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.0-RC.2") {
        because("required by walt.id")
    }
    implementation("com.augustcellars.cose:cose-java:1.1.0") {
        because("required by walt.id")
    }
    implementation(libs.uri.kmp) {
        because("To generate Credentials Offer URIs using custom URIs")
    }

    implementation("org.apache.cxf:cxf-rt-frontend-jaxws:4.0.4")
    implementation("org.apache.cxf:cxf-rt-ws-security:4.0.4") {
        exclude(group = "com.google.j2objc")
    }
    implementation("org.apache.cxf:cxf-rt-transports-http:4.0.4")
}

java {
    val javaVersion = libs.versions.java.get()
    sourceCompatibility = JavaVersion.toVersion(javaVersion)
}

kotlin {
    jvmToolchain {
        val javaVersion = libs.versions.java.get()
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    }
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        freeCompilerArgs += "-Xcontext-receivers"
        freeCompilerArgs += "-Xjsr305=strict"
    }
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    environment.set(System.getenv())
    val env = environment.get()
    docker {
        publishRegistry {
            env["REGISTRY_URL"]?.let { url = it }
            env["REGISTRY_USERNAME"]?.let { username = it }
            env["REGISTRY_PASSWORD"]?.let { password = it }
        }
        env["DOCKER_METADATA_OUTPUT_TAGS"]?.let { tagStr ->
            tags = tagStr.split(delimiters = arrayOf("\n", " ")).onEach { println("Tag: $it") }
        }
    }
}

val wsdlResourceDirectory = "${project.layout.projectDirectory.dir("src/main/resources/eid-wsdl")}"
val wsdlResourceLocation = "eid-wsdl/TR-03130eID-Server.wsdl"
wsdl2java {
    locale = Locale.US
    encoding = UTF_8.name()

    cxfVersion = "4.0.4"
    cxfPluginVersion = "4.0.4"
    includeJava8XmlDependencies = false

    wsdlDir = File(wsdlResourceDirectory)

    wsdlsToGenerate = listOf(
        listOf(
            "-wsdlLocation",
            "classpath:$wsdlResourceLocation",
            "${wsdlResourceDirectory}/../$wsdlResourceLocation"
        )
    )
}
