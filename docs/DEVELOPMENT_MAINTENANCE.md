# How to update the Keycloak Plugin
The Keycloak plugin is packaged in a plugin image. This repo is mirrored to Party Pus IL2 where a mission dev ops (MDO) piline is run with security scans. The MDO pipeline creates a jar artifact that is hosted in [Iron Bank](https://ironbank.dso.mil/repomap/details;registry1Path=big-bang%252Fp1-keycloak-plugin). The plugin image can be pulled at `registry1.dso.mil/ironbank/big-bang/p1-keycloak-plugin:X.X.X`
1. Be aware that there are currently two versions of Keycloak. One is the legacy version that uses Wildfly for the application server. The other version is the new one using Quarkus. This plugin supports the new Keycloak Keycloak Quarkus. The new Keycloak images in Iron Bank have tag names without `legacy`.
1. Create a development branch and merge request. Can do this in the Gitlab UI from an issue.
1. Update /CHANGELOG.md with an entry for "upgrade Keycloak plugin to app version x.x.x. Or, whatever description is appropriate.
1. Update the keycloak library dependencies in the build.gradle file to match the new version of Keycloak. This Keycloak library update might cause build errors. You might have to fix code in `src/main/**.java` and `src/test/**.java` to get the build and unit tests to complete without errors.
1. Update any of the other gradle plugins as necessary. 
1. Follow instructions in the [deployment documentation](./deployment.md) to build and publish a plugin image.

# Testing new Keycloak version
The plugin can be tested locally and in a k8s environment

## Local development environment
Follow instructions in the P1 Keycloak package repo for how to develop with a [local docker-compse](https://repo1.dso.mil/platform-one/big-bang/apps/security-tools/keycloak/-/blob/main/development/README.md) environment.

## Development Testing with Kubernetes
Follow instructions in the [P1 Keycloak package repo](https://repo1.dso.mil/platform-one/big-bang/apps/security-tools/keycloak/-/blob/main/docs/DEVELOPMENT_MAINTENANCE.md) to delpoy Keycloak with plugin with Big Bang in Kubernetes.