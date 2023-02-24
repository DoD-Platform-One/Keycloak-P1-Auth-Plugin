# How to update the Keycloak Plugin
The Keycloak plugin is packaged in a plugin image. This repo is mirrored to Party Pus IL2 where a mission dev ops (MDO) pipeline is run with security scans. The MDO pipeline creates a jar artifact that is hosted in [Iron Bank](https://ironbank.dso.mil/repomap/details;registry1Path=big-bang%252Fp1-keycloak-plugin). The plugin image can be pulled at `registry1.dso.mil/ironbank/big-bang/p1-keycloak-plugin:X.X.X`
1. Be aware that there are two distributions of Keycloak. One is the legacy version that uses Wildfly for the application server. The other version is the new one using Quarkus. This plugin supports the new Keycloak Quarkus. The new Keycloak images in Iron Bank have tag names without `legacy`.
1. Create a development branch and merge request. Can do this in the Gitlab UI from an issue.
1. Recommended to use the free community version of Intellij IDEA instead of Visual Studio Code. Intellij IDEA has much better support for Java development. You can run unit tests with coverage and build from the IDE.
1. Update /CHANGELOG.md with an entry for "upgrade Keycloak plugin libraries to version x.x.x. Or, whatever description is appropriate.
1. Update the keycloak library dependencies in the p1-keycloak-plugin/build.gradle file to match the new version of Keycloak. This Keycloak library update might cause build errors. You might have to fix code in `src/main/**.java` and `src/test/**.java` to get the build and unit tests to complete without errors.
1. The plugin version is controlled by the top-level grade.properties. The built jar will be named with the semver from the gradle.properties. There is no hard rule for how to bump the semver X.X.X version. In general if the update is a patch upgrade or a bug fix then bump the patch number. If the plugin is getting a major or minor version upgrade of the Keycloak libraries then bump the minor number. If there are significant changes to the plugin, new features, or repo restructuring then bump the major version number.  
1. Update any of the other gradle plugins as needed.
1. Update the custom quarkus extension dependencies as needed in the quarkus-ext-routing/deployment project
1. Update the custom quarkus extension dependencies as needed in the quarkus-ext-routing/runtime project
1. Update any documentation as needed.
1. Follow instructions in the [deployment documentation](./deployment.md) to build and publish a plugin image.

# Testing new Keycloak version
The plugin can be tested locally and in a k8s environment. See instructions here and in the [deployment.md](deployment.md) doc for how to build project. 

## Local plugin development environment
Follow instructions in the P1 Keycloak package repo for how to do plugin development with a local [docker compse](https://repo1.dso.mil/big-bang/product/packages/keycloak/-/tree/main/development) environment.

## Local Quarkus Extension development environment
There is a custom Quarkus extension for routing and redirects packaged inside this repo. Maven commands can be used to launch a local development environment. Then you can test in your browser at `http://localhost:9005`.
    ```bash
    mvn clean install -f quarkus-ext-routing/runtime && mvn clean compile -f quarkus-ext-routing/deployment quarkus:dev -Dquarkus.enforceBuildGoal=false -Dquarkus.profile=quarkusdev
    ```
If you get "Non-resolvable parent POM" errors when running mvn commands your local cache needs to be cleared by running
    ```bash
    mvn clean install -N
    ```

## Development Testing with Kubernetes
Follow instructions in the [P1 Keycloak package repo](https://repo1.dso.mil/big-bang/product/packages/keycloak/-/blob/main/docs/DEVELOPMENT_MAINTENANCE.md) to deploy Keycloak with plugin with Big Bang in Kubernetes.

## Other development tasks to pass MDO pipeline
### Run linting
To run code linting locally on workstation
```bash
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
./gradlew lintGradle
```

### Run unit tests
An IDE is best for running unit tests to get code coverage. You can also run unit tests from command line on workstation.
Locally run the tests and generate the html report.
```bash
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
./gradlew clean test jacocoTestReport --info
```
Then open build/jacoco/html/index.html in a browser. This is the report that the pipeline uses and it typically shows less code coverage than the IDE.

### Sonarqube scan
Deploy your own Sonarqube using Big Bang with a k8s dev environment. Use the provided [sonar-project-dev.properties](../sonar-project-dev.properties). Follow the details in that sonar-scan config. Manually create a "keycloak-plugin" sonar project in the UI which will generate a token. You will need to do a clean build first because Sonarqube uses the built jar artifact.
```bash
./gradlew clean assemble
export SONAR_LOGIN=XXXXXXXXXXXXXXXXXXXXX
sonar-scanner -Dproject.settings=sonar-project-dev.properties
```
