- [Developer Guide](#developer-guide)
  - [Forking and Cloning](#forking-and-cloning)
  - [Install Prerequisites](#install-prerequisites)
    - [JDK 21](#jdk-21)
  - [Setup](#setup)
  - [Build](#build)
    - [Building from the command line](#building-from-the-command-line)
    - [Building from the IDE](#building-from-the-ide)

## Developer Guide

### Forking and Cloning

Fork this repository on GitHub, and clone locally with `git clone`.

### Install Prerequisites

#### JDK 21

OpenSearch builds using Java 21 at a minimum, using the Adoptium distribution. This means you must have a JDK 21 installed with the environment variable `JAVA_HOME` referencing the path to Java home for your JDK 21 installation, e.g. `JAVA_HOME=/usr/lib/jvm/jdk-21`. This is configured in [buildSrc/build.gradle](buildSrc/build.gradle) and [distribution/tools/java-version-checker/build.gradle](distribution/tools/java-version-checker/build.gradle).

```
allprojects {
  targetCompatibility = JavaVersion.VERSION_21
  sourceCompatibility = JavaVersion.VERSION_21
}
```

```
sourceCompatibility = JavaVersion.VERSION_21
targetCompatibility = JavaVersion.VERSION_21
```

Download Java 21 from [here](https://adoptium.net/releases.html?variant=openjdk21).

### Setup

1. Clone the repository (see [Forking and Cloning](#forking-and-cloning))
2. Make sure `JAVA_HOME` is pointing to a Java 21 JDK (see [Install Prerequisites](#install-prerequisites))
3. Launch Intellij IDEA, Choose Import Project and select the settings.gradle file in the root of this package.

### Build

This package uses the [Gradle](https://docs.gradle.org/current/userguide/userguide.html) build system. Gradle comes with excellent documentation that should be your first stop when trying to figure out how to operate or modify the build. We also use the OpenSearch build tools for Gradle. These tools are idiosyncratic and don't always follow the conventions and instructions for building regular Java code using Gradle. Not everything in this package will work the way it's described in the Gradle documentation. If you encounter such a situation, the OpenSearch build tools [source code](https://github.com/opensearch-project/OpenSearch/tree/main/buildSrc/src/main/groovy/org/opensearch/gradle) is your best bet for figuring out what's going on.

#### Building from the command line

1. `./gradlew build` builds and tests all subprojects.
2. `./gradlew run` launches a single node cluster with the security analytics plugin installed.

When launching a cluster using one of the above commands, logs are placed in `build/testclusters/integTest-0/logs/`. Though the logs are teed to the console, in practice it's best to check the actual log file.

#### Building from the IDE

Currently, the only IDE we support is IntelliJ IDEA.  It's free, it's open source, it works. The gradle tasks above can also be launched from IntelliJ's Gradle toolbar and the extra parameters can be passed in via the Launch Configurations VM arguments.

### Backport

- [Link to backport documentation](https://github.com/opensearch-project/opensearch-plugins/blob/main/BACKPORT.md)
