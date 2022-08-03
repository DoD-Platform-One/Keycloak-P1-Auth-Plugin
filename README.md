# Keycloak P1 Auth Plugin
Repository for the Platform One Keycloak Plugin. This plugin has passed scans in the Party Bus IL2 DevSecOps pipeline. The Keycloak plugin has custom themes and authentication flows. This code is specific to the Platform One SSO delpoyment because it has some hard-coded email and web links that point to *.dsop.mil and *.dso.mil.

# Credits
Commit history could not be preserved. Credit goes to Jeff McCoy who developed the original plugin. The plugin is now maintained by Platform One.

# Deployment Overview
Jar files are deployed by placing them in `$KEYCLOAK_HOME\standalone\deployments`. They will be detected and deployed by the application server. In a containerized k8s environment this happens by putting the jar in an image and deploying the image as an additional init-container when Keycloak deploys. Keycloak k8s upstream is changing from Wildfly application server to something called [Quarkus](https://www.keycloak.org/migration/migrating-to-quarkus). This will significantly change the delpoyment configuration in the near future. 


# Deployment Details
This documentation is intended to outline the manual steps so that it can be automated with configuration as code(CaC).

## Build
First build this plugin project to create a jar file. This is a Java Gradle project. You can build it from an IDE or from command line. Here is how to build it from a docker container without installing dependencies on your workstation. The java archive(jar) will be created at /build/libs/platform-one-sso-x.x.x.jar. The plugin uses semantic versioning controlled by the "version" in the build.gradle configuration.
```
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
gradle clean --build-cache assemble
```

## Build a plugin image
Build an image that contains the jar and the x509.sh script. Change the image tag to match the location where you will host the image. And update the version if it does not match the version being built. Example:
```
docker build -t registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:2.0.6 .
```
Verify the contents of the plugin image. It should contain the jar and the x509 script.
```
docker run -it --rm registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:2.0.6 /bin/bash
ls -l
```
Push the plugin image to your image registry. Example:
```
docker push registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:2.0.6
```
## Deploy plugin with k8s init-container
The following config is an example Big Bang vaules file to delpoy Keycloak with the plugin. Take note of the following details:

- The Keycloak deployment uses the base Keycloak image from Iron Bank instead of a custom image.
- The plugin jar is copied into the Keycloak container by the init-container.
- The init-container uses the k8s emptyDir for the volume. The emptyDir volume is shared between all containers in a pod. This is what allows the plugin jar to be copied into the Keycloak container.

Change the plugin image registry to match where you hosted the plugin image. For this demonstration we are only deploying istio, istio operator, Keycloak, and Gitlab. Gitlab is deployed in order to test end-to-end SSO. All other core apps and addons are disabled.
```
domain: bigbang.dev

flux:
  interval: 1m
  rollback:
    cleanupOnFail: false

networkPolicies:
  enabled: true

clusterAuditor:
  enabled: false

gatekeeper:
  enabled: false

kyverno:
  enabled: false

kyvernopolicies:
  enabled: false

istiooperator:
  enabled: true

istio:
  enabled: true
  ingressGateways:
    public-ingressgateway:
      type: "LoadBalancer"
    passthrough-ingressgateway:
      type: "LoadBalancer"
  gateways:
    public:
      ingressGateway: "public-ingressgateway"
      hosts:
      - "*.{{ .Values.domain }}"
    passthrough:
      ingressGateway: "passthrough-ingressgateway"
      hosts:
      - "*.{{ .Values.domain }}"
      tls:
        mode: "PASSTHROUGH"

jaeger:
  enabled: false

kiali:
  enabled: false

logging:
  enabled: false

eckoperator:
  enabled: false

fluentbit:
  enabled: false

monitoring:
  enabled: false

twistlock:
  enabled: false

# Gloabl SSO parameters
sso:
  oidc:
    host: keycloak.bigbang.dev
    realm: baby-yoda

addons:

  metricsServer:
    enabled: false
    
  keycloak:
    enabled: true
    ingress:
      gateway: "passthrough"
    values:
      replicas: 1
      # networkPolicies:
      #   enabled: false
      image:
        repository: registry1.dso.mil/ironbank/opensource/keycloak/keycloak
        tag: 18.0.2-legacy
      secrets:
        env:
          stringData:
            CUSTOM_REGISTRATION_CONFIG: /opt/jboss/keycloak/customreg.yaml
            KEYCLOAK_IMPORT: /opt/jboss/keycloak/realm.json
            X509_CA_BUNDLE: /etc/x509/https/cas.pem
        certauthority:
          stringData:
            cas.pem: '{{ .Files.Get "resources/dev/dod_cas.pem" }}'
        customreg:
          stringData:
            customreg.yaml: '{{ .Files.Get "resources/dev/baby-yoda.yaml" }}'
        realm:
          stringData:
            realm.json: '{{ .Files.Get "resources/dev/baby-yoda.json" }}'
      extraInitContainers: |-
        - name: plugin
          image: registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:2.0.6
          imagePullPolicy: Always
          command:
          - sh
          - -c
          - | 
            cp /app/platform-one-sso-2.0.6.jar /init
            cp /app/x509.sh /init
            ls -l /init
          volumeMounts:
          - name: plugin
            mountPath: "/init"
      extraVolumes: |-
        - name: certauthority
          secret:
            secretName: {{ include "keycloak.fullname" . }}-certauthority
        - name: customreg
          secret:
            secretName: {{ include "keycloak.fullname" . }}-customreg
        - name: realm
          secret:
            secretName: {{ include "keycloak.fullname" . }}-realm
        - name: plugin
          emptyDir: {}
      extraVolumeMounts: |-
        - name: certauthority
          mountPath: /etc/x509/https/cas.pem
          subPath: cas.pem
          readOnly: true
        - name: customreg
          mountPath: /opt/jboss/keycloak/customreg.yaml
          subPath: customreg.yaml
          readOnly: true
        - name: realm
          mountPath: /opt/jboss/keycloak/realm.json
          subPath: realm.json
          readOnly: true
        - name: plugin
          mountPath: /opt/jboss/keycloak/standalone/deployments/platform-one-sso-2.0.6.jar
          subPath: platform-one-sso-2.0.6.jar
        - name: plugin
          mountPath: /opt/jboss/tools/x509.sh
          subPath: x509.sh
      startupScripts:
        # WildFly CLI script for configuring the node-identifier
        bigbang.cli: |
          embed-server --server-config=standalone-ha.xml --std-out=echo
          batch
          ## Sets the node identifier to the node name (= pod name). Node identifiers have to be unique. They can have a
          ## maximum length of 23 characters. Thus, the chart's fullname template truncates its length accordingly.
          /subsystem=transactions:write-attribute(name=node-identifier, value=${jboss.node.name})

          # Allow log level to be configured via environment variable
          /subsystem=logging/console-handler=CONSOLE:write-attribute(name=level, value=${env.WILDFLY_LOGLEVEL:INFO})
          /subsystem=logging/root-logger=ROOT:write-attribute(name=level, value=${env.WILDFLY_LOGLEVEL:INFO})

          # Add dedicated eventsListener config element to allow configuring elements.
          /subsystem=keycloak-server/spi=eventsListener:add()
          /subsystem=keycloak-server/spi=eventsListener/provider=jboss-logging:add(enabled=true)

          # Propagate success events to INFO instead of DEBUG, to expose successful logins for log analysis
          /subsystem=keycloak-server/spi=eventsListener/provider=jboss-logging:write-attribute(name=properties.success-level,value=info)
          /subsystem=keycloak-server/spi=eventsListener/provider=jboss-logging:write-attribute(name=properties.error-level,value=warn)

          # Configure datasource to use explicit query timeout in seconds
          /subsystem=datasources/data-source=KeycloakDS/:write-attribute(name=query-timeout,value=${env.DB_QUERY_TIMEOUT:300})

          # Configure datasource to connection before use
          /subsystem=datasources/data-source=KeycloakDS/:write-attribute(name=validate-on-match,value=${env.DB_VALIDATE_ON_MATCH:true})

          # Configure datasource to try all other connections before failing
          /subsystem=datasources/data-source=KeycloakDS/:write-attribute(name=use-fast-fail,value=${env.DB_USE_CAST_FAIL:false})

          /subsystem=infinispan/cache-container=keycloak/distributed-cache=sessions:write-attribute(name=owners, value=${env.CACHE_OWNERS:2})
          /subsystem=infinispan/cache-container=keycloak/distributed-cache=authenticationSessions:write-attribute(name=owners, value=${env.CACHE_OWNERS:2})
          /subsystem=infinispan/cache-container=keycloak/distributed-cache=offlineSessions:write-attribute(name=owners, value=${env.CACHE_OWNERS:2})
          /subsystem=infinispan/cache-container=keycloak/distributed-cache=clientSessions:write-attribute(name=owners, value=${env.CACHE_OWNERS:2})
          /subsystem=infinispan/cache-container=keycloak/distributed-cache=offlineClientSessions:write-attribute(name=owners, value=${env.CACHE_OWNERS:2})
          /subsystem=infinispan/cache-container=keycloak/distributed-cache=loginFailures:write-attribute(name=owners, value=${env.CACHE_OWNERS:2})
          /subsystem=infinispan/cache-container=keycloak/distributed-cache=actionTokens:write-attribute(name=owners, value=${env.CACHE_OWNERS:2})

          /subsystem=jgroups/channel=ee:write-attribute(name=stack, value=tcp)

          /subsystem=undertow/configuration=filter/expression-filter=baby-yoda:add(expression="path('/auth/') -> redirect('/auth/realms/baby-yoda/account')")
          /subsystem=undertow/server=default-server/host=default-host/filter-ref=baby-yoda:add

          # Shortcut for /register
          /subsystem=undertow/configuration=filter/expression-filter=register:add(expression="path('/register') -> redirect('/auth/realms/baby-yoda/protocol/openid-connect/registrations?client_id=account&response_type=code')")
          /subsystem=undertow/server=default-server/host=default-host/filter-ref=register:add

          # Special handlers for mattermost oidc
          /subsystem=undertow/configuration=filter/expression-filter=mm-auth-login:add(expression="path-prefix('/oauth/authorize') -> redirect('/auth/realms/baby-yoda/protocol/openid-connect/auth%{QUERY_STRING}')")
          /subsystem=undertow/server=default-server/host=default-host/filter-ref=mm-auth-login:add
          /subsystem=undertow/configuration=filter/rewrite==mm-auth-user:add(target="/auth/realms/baby-yoda/protocol/openid-connect/userinfo%{QUERY_STRING}")
          /subsystem=undertow/server=default-server/host=default-host/filter-ref=mm-auth-user:add(predicate="path-prefix('/api/v4/user')")
          /subsystem=undertow/configuration=filter/rewrite==mm-auth-token:add(target="/auth/realms/baby-yoda/protocol/openid-connect/token%{QUERY_STRING}")
          /subsystem=undertow/server=default-server/host=default-host/filter-ref=mm-auth-token:add(predicate="path-prefix('/oauth/token')")

          # Enable Declarative User Profile to support modifying attributes aka usercertificate (Version 14 only)
          /subsystem=keycloak-server/spi=userProfile:add(default-provider=declarative-user-profile)

          run-batch
          stop-embedded-server

  # deploy Gitlab to test end-to-end SSO
  gitlab:
    enabled: true
    ingress:
      gateway: "public"
    hostnames:
      gitlab: gitlab
      registry: registry
    sso:
      enabled: true
      label: "Platform One SSO"
      client_id: "dev_00eb8904-5b88-4c68-ad67-cec0d2e07aa6_gitlab"
      client_secret: ""
    values:
      gitlab: 
        webservice:
          minReplicas: 1
          maxReplicas: 1
        gitlab-shell:
          minReplicas: 1
          maxReplicas: 1
        sidekiq:
          minReplicas: 1
          maxReplicas: 1
      registry:
        hpa:
          minReplicas: 1
          maxReplicas: 1
      global:
        appConfig:
          defaultCanCreateGroup: true
```

# Other development tasks
## Run linting
To run code linting locally on workstation
```
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
gradle lintGradle
```

## Run unit tests
An IDE is best for runnnig unit tests to get code coverage. You can also run unit tests unit tests from command line on workstation. Temporarily modify build.gradle to output jacoco html report
```
jacocoTestReport {
    reports {
        html.enabled true
        html.destination file("${buildDir}/jacoco/html/")
        csv.enabled false
        xml.enabled true
        xml.destination file("${buildDir}/jacoco/test.xml")
    }
}
```
Locally run the tests and generate the htlm report
```
docker run -it --rm -v $(pwd):/app registry1.dso.mil/ironbank/opensource/gradle/gradle-jdk11:7.4.2 bash
cd /app
gradle clean
gradle test
gradle jacocoTestReport
```
