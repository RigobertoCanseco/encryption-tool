plugins {
    java
}

group = "com.rigobertocanseco"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    compile ("commons-codec", "commons-codec", "1.1")
    testCompile("junit", "junit", "4.12")
}

configure<JavaPluginConvention> {
    sourceCompatibility = JavaVersion.VERSION_1_6
}