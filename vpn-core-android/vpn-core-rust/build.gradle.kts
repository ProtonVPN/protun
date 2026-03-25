/*
 * Copyright (c) 2025. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

plugins {
    alias(coreLibs.plugins.rustandroid)
    alias(coreLibs.plugins.android.library)
    alias(coreLibs.plugins.kotlin.android)
}

android {
    namespace = "me.proton.vpn.core_rust"
    compileSdk = coreLibs.versions.compileSdk.get().toInt()
    ndkVersion = "28.1.13356709"

    defaultConfig {
        aarMetadata {
            minCompileSdk = coreLibs.versions.minCompileSdk.get().toInt()
        }
        minSdk = coreLibs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false // Let's leave it to library users to minify and optimize.
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            packaging.jniLibs.keepDebugSymbols.add("**/*.so")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

val rustCrateName = "protun"
val rustCratePath = "../.."
val generatedUniffiDirectory = layout.buildDirectory.file("generated/uniffi/java")
val rustProfile = "release"

cargo {
    module = rustCratePath
    libname = rustCrateName
    targets = buildList {
        addAll(listOf("arm", "arm64", "x86", "x86_64"))
    }
    features {
        defaultAnd(arrayOf("android", "uniffi"))
    }
    prebuiltToolchains = true
    apiLevel = 25
    profile = rustProfile
}

val generateUniFFIBindingsTask = tasks.register<Exec>("generateUniFFIBindings") {
    dependsOn += "cargoBuild"
    workingDir = file(rustCratePath)
    commandLine = listOfNotNull(
        "cargo", "run", "--features", "uniffi", if (rustProfile == "release") "--release" else null, "--bin", "uniffi-bindgen",
        "generate", "--library", "target/aarch64-linux-android/$rustProfile/lib${rustCrateName}.so",
        "--language", "kotlin", "--config", "uniffi.toml",
        "--out-dir", generatedUniffiDirectory.get().asFile.path
    )
}
dependencies {
    implementation(libs.androidx.annotation)
    implementation(libs.jna) {
        artifact { type = "aar" }
    }
}

tasks.clean {
    delete("${rustCratePath}/target")
}

android.libraryVariants.configureEach {
    // generateUniFFIBindingsTask is an Exec task that doesn't define outputs, explicitly add the folder with generated
    // source files.
    registerJavaGeneratingTask(generateUniFFIBindingsTask, generatedUniffiDirectory.get().asFile)
}
