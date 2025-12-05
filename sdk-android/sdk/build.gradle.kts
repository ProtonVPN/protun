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
    alias(sdkLibs.plugins.android.library)
    alias(sdkLibs.plugins.kotlin.android)
    alias(sdkLibs.plugins.hilt.android)
    alias(sdkLibs.plugins.ksp)
    id("kotlin-parcelize")
}

// By default (standalone sdk) sdk-rust will provide rust library with bindings. In embedded mode
// parent library will provide alternative rust module.
val rustProviderModule = findProperty("protunSdkRustProviderModule") as String? ?: ":sdk-rust"

android {
    namespace = "me.proton.vpn.sdk"
    compileSdk = sdkLibs.versions.compileSdk.get().toInt()
    ndkVersion = "28.1.13356709"

    defaultConfig {
        aarMetadata {
            minCompileSdk = sdkLibs.versions.minCompileSdk.get().toInt()
        }
        minSdk = sdkLibs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false // Let's leave it to library users to minify and optimize.
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
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

dependencies {
    implementation(sdkLibs.androidx.annotation)
    implementation(sdkLibs.hilt.android)
    ksp(sdkLibs.hilt.compiler)
    api(project(rustProviderModule))
}
