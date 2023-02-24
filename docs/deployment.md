# Deployment Overview
Jar files are deployed with Keycloak by placing them in `/opt/keycloak/providers/` directory. In a containerized k8s environment this happens by putting the jar in an plugin image and deploying the image as an additional init-container when Keycloak deploys. Keycloak k8s upstream is changing from Wildfly application server to  [Quarkus](https://www.keycloak.org/migration/migrating-to-quarkus). This plugin supports the new Keycloak Quarkus.
This repo includes a custom Quarkus extension for routing and redirects. It is configurable with quarkus.properties. See the [development properties file](/quarkus-ext-routing/deployment/src/main/resources/application-quarkusdev.properties) for examples of how to configure. Also see [example k8s operational values](https://repo1.dso.mil/big-bang/bigbang/-/blob/master/docs/assets/configs/example/keycloak-prod-values.yaml).

## Deployment Details
This documentation is intended to outline the manual steps so that it can be automated with configuration as code(CaC).

### Build
First build this plugin project to create a jar file. This is a Java Gradle project. You can build it from an IDE or from command line. Here is how to build it from a docker container without installing dependencies on your workstation. If you want to build on your workstation without the gradle image you will need to install the appropriate versions of JDK and gradle. The java archive(jar) will be created at /build/libs/p1-keycloak-plugin-x.x.x.jar. The plugin uses semantic versioning controlled by the "version" in the top level gradle.properties configuration.
```
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
./gradlew clean --build-cache assemble
```

### Build a plugin image
Build an image that contains the plugin jar. The official plugin image is hosted in [Iron Bank](https://ironbank.dso.mil/repomap/details;registry1Path=big-bang%252Fp1-keycloak-plugin) available to be pulled at `registry1.dso.mil/ironbank/big-bang/p1-keycloak-plugin:X.X.X`. DO NOT configure production deployments using registry.dso.mil. The registry.dso.mil is for development testing only by the Big Bang Product team. For development, change the image tag to match the location where you will host the image. And update the version if it does not match the version being built. These commands are for example only. Note that the Dockerfile matches the Dockerfile from the [Iron Bank dosp repository](https://repo1.dso.mil/dsop/big-bang/p1-keycloak-plugin/-/blob/development/Dockerfile). Example:
```
docker build -t registry1.dso.mil/bigbang-staging/keycloak-p1-auth-plugin/init-container:test-X.X.X .
```
Verify the contents of the plugin image. It should contain the plugin jar. Example:
```
docker run -it --rm registry1.dso.mil/bigbang-staging/keycloak-p1-auth-plugin/init-container:test-X.X.X /bin/bash
ls -l
```
Push the plugin image to your image registry. Example:
```
docker push registry1.dso.mil/bigbang-staging/keycloak-p1-auth-plugin/init-container:test-X.X.X
``` 
    
### Deploy plugin with k8s init-container
Example Big Bang deployment values to deploy Keycloak with the plugin are available at [development values](https://repo1.dso.mil/big-bang/bigbang/-/blob/master/docs/assets/configs/example/keycloak-dev-values.yaml) and [example operational values](https://repo1.dso.mil/big-bang/bigbang/-/blob/master/docs/assets/configs/example/keycloak-prod-values.yaml). Take note of the following details:
- The Keycloak deployment uses the base Keycloak image from Iron Bank instead of a custom image.
- The plugin jar is injected into the Keycloak container on startup by an init-container.
- The init-container uses the k8s emptyDir for the volume. The emptyDir volume is shared between all containers in a pod. This is what allows the plugin jar to be copied into the Keycloak container.

