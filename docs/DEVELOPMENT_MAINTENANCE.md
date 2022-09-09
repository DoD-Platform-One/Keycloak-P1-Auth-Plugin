# How to update the Keycloak Plugin
The Keycloak plugin is packaged in a plugin image. It will eventually be hosted in Iron Bank.
1. Be aware that there are currently two versions of Keycloak. One is the legacy version that uses Wildfly for the application server. The other version is the new one using Quarkus. Big Bang for now will remain with the legacy version. The images in Iron Bank have tag with ```X.X.X-legacy```.
1. Create a development branch and merge request. Can do this in the Gitlab UI from an issue.
1. Update /CHANGELOG.md with an entry for "upgrade Keycloak plugin to app version x.x.x. Or, whatever description is appropriate.
1. Update the keycloak library dependencies in the build.gradle file to match the new version of Keycloak. This Keycloak library update might cause build errors. You might have to fix code in `src/main/**.java` and `src/test/**.java` to get the build and unit tests to complete without errors.
1. Update any of the other gradle plugins as necessary. 
1. Follow instructions in the top-level README.md for how to build and deploy.

# Testing new Keycloak version
1. Create a k8s dev environment. One option is to use the Big Bang [k3d-dev.sh](https://repo1.dso.mil/platform-one/big-bang/bigbang/-/blob/master/docs/assets/scripts/developer/k3d-dev.sh) with the ```-m``` for metalLB so that k3d can support multiple ingress gateways. The following steps assume you are using the script.
1. Follow the instructions at the end of the script to ssh to the EC2 instance with application-level port forwarding. Keep this ssh session for the remainder of the testing. 
1. You will need to edit the /etc/hosts on the EC2 instance. Make it look like this
    ```bash
    ## begin bigbang.dev section
    172.20.1.240 keycloak.bigbang.dev
    172.20.1.241 gitlab.bigbang.dev sonarqube.bigbang.dev
    ## end bigbang.dev section
    ```
1. For end-to-end SSO testing there needs to be DNS for Keycloak. In a k3d dev environment there is no DNS so you must do a dev hack and edit the configmap "coredns-xxxxxxxx". Under NodeHosts add a host for keycloak.bigbang.dev.    
    ```
    kubectl get cm -n kube-system   
    kubectl edit cm coredns -n kube-system   
    ```

    The IP for keycloak in a k3d environment created by the dev script will be 172.20.1.240. Like this  
    ```yaml
    NodeHosts: |
    <nil>      host.k3d.internal
    172.20.0.2 k3d-k3s-default-agent-0
    172.20.0.5 k3d-k3s-default-agent-1
    172.20.0.4 k3d-k3s-default-agent-2
    172.20.0.3 k3d-k3s-default-server-0
    172.20.0.6 k3d-k3s-default-serverlb
    172.20.1.240 keycloak.bigbang.dev
    ```

1. Restart the coredns pod so that it picks up the new configmap.
    ```
    kubectl get pods -A   
    kubectl delete pod <coredns pod> -n kube-system
    ```

1. Deploy Big Bang with only istio-operator, istio, gitlab, and sonarqube enabled. Need to test both OIDC and SAML end-to-end SSO. Gitlab uses OIDC and Sonarqube uses SAML. Deploy BigBang using the following example helm command
    ```
    helm upgrade -i bigbang ./chart -n bigbang --create-namespace -f ../overrides/my-bb-override-values.yaml -f ../overrides/registry-values.yaml -f ./chart/ingress-certs.yaml
    ```
    and these example values overrides (be sure to update the keycloak branch in the overrides below)
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
            tag: 19.0.1-legacy
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
            image: registry.dso.mil/platform-one/big-bang/apps/product-tools/keycloak-p1-auth-plugin/init-container:2.2.0
            imagePullPolicy: Always
            command:
            - sh
            - -c
            - | 
                cp /app/platform-one-sso-2.2.0.jar /init
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
            mountPath: /opt/jboss/keycloak/standalone/deployments/platform-one-sso-2.2.0.jar
            subPath: platform-one-sso-2.2.0.jar
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

       sonarqube:
        enabled: true
        ingress:
          gateway: "public"
        sso:
          enabled: true
          client_id: "dev_00eb8904-5b88-4c68-ad67-cec0d2e07aa6_saml-sonarqube"
          label: "keycloak sso"
          # this is the Keycloak realm cert. Get it froum the Keycloak admin console
          certificate: "single-line-string-keycloak-realm-cert"
          login: login
          name: name
          email: email
          group: group           
    ```
1. Sonarqube needs an extra configuration step for SSO to work because it uses SAML. The values override ```addons.sonarqube.sso.certificate``` needs to be updated with the Keycloak realm certificate. When Keycloak finishes installing login to the admin console [Keycloak](https://keycloak.bigbang.dev/auth/admin) with default credentials ```admin/password```. Navigate to Realm Settings >> Keys. On the RS256 row click on the ```Certificate``` button and copy the certificate text as a single line string and paste it into your ```addons.sonarqube.sso.certificate``` value. Run another ```helm upgrade``` command and watch for Sonarqube to update.
1. Use Firefox browser with SOCKS v5 manual proxy configured so that we are running Firefox as if it was running on the EC2 instance. This is described in more detail in the development environment addendum [Multi Ingress-gateway Support with MetalLB and K3D](https://repo1.dso.mil/platform-one/big-bang/bigbang/-/blob/master/docs/developer/development-environment.md)
1. In the Firefox browser load ```https://keycloak.bigbang.dev``` and register a test user. You should register yourself with CAC and also a non-CAC test.user with just user and password with OTP. Both flows need to be tested.
1. Then go back to ```https://keycloak.bigbang.dev/auth/admin``` and login to the admin console with the default credentials ```admin/password```
1. Navigate to users, click "View all users" button and edit the test users that you created. Set "Email Verified" ON. Remove the verify email "Required User Actions". Click "Save" button.
1. Test end-to-end SSO with Gitlab and Sonarqube with your CAC user and the other test user.
1. Test the custom user forms to make sure all the fields are working
    - https://keycloak.bigbang.dev/auth/realms/baby-yoda/account/
    - https://keycloak.bigbang.dev/auth/realms/baby-yoda/account/password
    - https://keycloak.bigbang.dev/auth/realms/baby-yoda/account/totp
    - https://keycloak.bigbang.dev/register

