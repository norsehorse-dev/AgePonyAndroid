plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.agepony.core"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        minSdk = 21
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    testOptions {
        unitTests.all {
            it.useJUnitPlatform()
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    // bcprov 1.79 is the first release with the finalized FIPS 203 ML-KEM
    // (org.bouncycastle.pqc.crypto.mlkem). 1.78.1 predates it, so the PQC core
    // requires >= 1.79. Classic APIs (SHA-256, HKDF, ChaCha20Poly1305, X25519)
    // are unchanged from 1.78.1.
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
