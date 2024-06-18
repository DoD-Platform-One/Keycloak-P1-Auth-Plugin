# Deployment Overview
Jar files are deployed with Keycloak by placing them in `/opt/keycloak/providers/` directory. In a containerized k8s environment this happens by putting the jar in an plugin image and deploying the image as an additional init-container when Keycloak deploys. Keycloak k8s upstream is changing from Wildfly application server to  [Quarkus](https://www.keycloak.org/migration/migrating-to-quarkus). This plugin supports the new Keycloak Quarkus.
This repo includes a custom Quarkus extension for routing and redirects. It is configurable with quarkus.properties. See the [development properties file](/quarkus-ext-routing/deployment/src/main/resources/application-quarkusdev.properties) for examples of how to configure. Also see [example k8s operational values](https://repo1.dso.mil/big-bang/bigbang/-/blob/master/docs/assets/configs/example/keycloak-prod-values.yaml).

## Deployment Details
This documentation is intended to outline the manual steps so that it can be automated with configuration as code(CaC).

### Build
First build this plugin project to create a jar file. This is a Java Gradle project. You can build it from an IDE or from command line. Here is how to build it from a docker container without installing dependencies on your workstation. If you want to build on your workstation without the gradle image you will need to install the appropriate versions of JDK and gradle. The java archive(jar) will be created at /build/libs/p1-keycloak-plugin-x.x.x.jar. The plugin uses semantic versioning controlled by the "version" in the top level gradle.properties configuration.  
  
First, spin up a build container :
```bash
docker run -it --rm \
    --platform linux/amd64 \
    --entrypoint=bash \
    --user 0 \
    --volume $(pwd):/app \
    registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk17:8.3
```
Then build the app :
```bash
cd /app
./gradlew clean --build-cache assemble
```

### Build a plugin image
Build an image that contains the plugin jar. The official plugin image is hosted in [Iron Bank](https://ironbank.dso.mil/repomap/details;registry1Path=big-bang%252Fp1-keycloak-plugin) available to be pulled at `registry1.dso.mil/ironbank/big-bang/p1-keycloak-plugin:X.X.X`. DO NOT configure production deployments using registry.dso.mil. The registry.dso.mil is for development testing only by the Big Bang Product team. For development, change the image tag to match the location where you will host the image and update the version if it does not match the version being built. _These below commands are for example only._ Note that the Dockerfile matches the Dockerfile from the [Iron Bank dsop repository](https://repo1.dso.mil/dsop/big-bang/p1-keycloak-plugin/-/blob/development/Dockerfile).  
  
Build the image:
```bash
docker build -t registry1.dso.mil/bigbang-staging/keycloak-p1-auth-plugin/init-container:test-3.3.4 .
```
Verify the built image contains the plugin jar:
```bash
docker run -it --rm \
    registry1.dso.mil/bigbang-staging/keycloak-p1-auth-plugin/init-container:test-3.3.4 \
    sh -c "pwd && ls -lah | grep keycloak"
```
There it is:
```bash
/app
-rwxr-xr-x 1 root root  23M May  3 18:33 p1-keycloak-plugin-3.3.4.jar
```
Push the image to the staging registry:
```bash
docker push registry1.dso.mil/bigbang-staging/keycloak-p1-auth-plugin/init-container:test-3.3.4
```

### Deploy plugin with k8s init-container
Example Big Bang deployment values to deploy Keycloak with the plugin are available at [development values](https://repo1.dso.mil/big-bang/bigbang/-/blob/master/docs/assets/configs/example/keycloak-dev-values.yaml) and [example operational values](https://repo1.dso.mil/big-bang/bigbang/-/blob/master/docs/assets/configs/example/keycloak-prod-values.yaml).  
  
Take note of the following details:
- The Keycloak deployment uses the base Keycloak image from Iron Bank instead of a custom image.
- The plugin jar is injected into the Keycloak container on startup by an init-container.
- The init-container uses an `emptyDir` for the volume that is shared between all containers in the pod and this allows the plugin jar to be copied into the Keycloak container.  
  
Use the new recently pushed image and ensure the `cp` command matches the .jar filename:
```yaml
extraInitContainers: |-
  - name: plugin
    image: registry1.dso.mil/bigbang-staging/keycloak-p1-auth-plugin/init-container:test-3.3.4
    imagePullPolicy: Always
    command:
    - sh
    - -c
    - |
      cp /app/p1-keycloak-plugin.jar /init
      ls -l /init
    volumeMounts:
    - name: plugin
      mountPath: "/init"
```
Enable a service, such as Grafana below, that uses SSO to test the plugin:
```yaml
grafana:
  sso:
    enabled: true
    grafana:
      scopes: "openid Grafana"
      client_id: dev_00eb8904-5b88-4c68-ad67-cec0d2e07aa6_grafana
```
...you can even change the `keycloak` subdomain name exposed by Istio [here](https://repo1.dso.mil/big-bang/product/packages/keycloak/-/blob/main/chart/values.yaml?ref_type=heads#L633) if you'd like.
### Testing the plugin
Register a new user:
- Hit your [Grafana instance](https://grafana.dev.bigbang.mil) (or other SSO enabled service).
- `Sign in with P1 SSO`
- `No account? Click here to register now.`
- Fill out info for a new user.
- Setup MFA and stop at the email confirmation step.
- Jump over to the [admin area](https://keycloak.dev.bigbang.mil/auth/admin) and login `admin/password`.
- Switch to the `baby-yoda` realm and find the new user.
- Delete the email confirm step and mark the user as email confirmed; save.
- Jump to the groups tabs and add the user to the IL2 group.  
  
You should now be able to login as the new user to any of your enabled SSO servics and you can also reach the Keycloak user account profile page by going [here](https://keycloak.dev.bigbang.mil/auth/realms/baby-yoda/account).

*Note: May 2024 ~ CAC auth is still inconsistent without the dev plugin from zacw and the keycloak issue regarding 23.0.7 breaking CAC*
