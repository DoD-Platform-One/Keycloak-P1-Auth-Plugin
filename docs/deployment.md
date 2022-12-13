# Deployment Overview
Jar files are deployed by placing them in `/opt/keycloak/providers/` directory. They will be detected and deployed by the application server. In a containerized k8s environment this happens by putting the jar in an plugin image and deploying the image as an additional init-container when Keycloak deploys. Keycloak k8s upstream is changing from Wildfly application server to  [Quarkus](https://www.keycloak.org/migration/migrating-to-quarkus). This plugin support the new Keyloak Quarkus.

# Deployment Details
This documentation is intended to outline the manual steps so that it can be automated with configuration as code(CaC).

## Build
First build this plugin project to create a jar file. This is a Java Gradle project. You can build it from an IDE or from command line. Here is how to build it from a docker container without installing dependencies on your workstation. The java archive(jar) will be created at /build/libs/p1-keycloak-plugin-x.x.x.jar. The plugin uses semantic versioning controlled by the "version" in the build.gradle configuration.
```
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
./gradlew clean --build-cache assemble
```

## Build a plugin image
Build an image that contains the plugin jar. Change the image tag to match the location where you will host the image. And update the version if it does not match the version being built. Example:
```
docker build -t registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:3.0.0 .
```
Verify the contents of the plugin image. It should contain the plugin jar.
```
docker run -it --rm registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:3.0.0 /bin/bash
ls -l
```
Push the plugin image to your image registry. Example:
```
docker push registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:3.0.0
```

## Deploy plugin with k8s init-container
Example Big Bang deployment values to deploy Keycloak with the plugin are in progress and will be provided when available. Take note of the following details:
- The Keycloak deployment uses the base Keycloak image from Iron Bank instead of a custom image.
- The plugin jar is copied into the Keycloak container by the init-container.
- The init-container uses the k8s emptyDir for the volume. The emptyDir volume is shared between all containers in a pod. This is what allows the plugin jar to be copied into the Keycloak container.

Change the plugin image registry to match where you hosted the plugin image. For this demonstration we are only deploying istio, istio operator, Keycloak, and Gitlab. Gitlab is deployed in order to test end-to-end SSO. All other core apps and addons are disabled.


# Other development tasks
## Run linting
To run code linting locally on workstation
```
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
./gradlew lintGradle
```

## Run unit tests
An IDE is best for running unit tests to get code coverage. You can also run unit tests from command line on workstation.
Locally run the tests and generate the html report.
```
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
./gradlew clean test jacocoTestReport --info
```
Then open build/jacoco/html/index.html in a browser.
