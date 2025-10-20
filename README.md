# Keycloak P1 Auth Plugin
Repository for the Platform One Keycloak Plugin. This plugin has passed scans in the Party Bus IL2 MissionDevOps pipeline. The Keycloak plugin has custom themes and authentication flows. The project also contains a custom quarkus extension for routing. This code is specific to the Platform One SSO deployment because it has some hard-coded email and web links in the theme that point to *.dsop.mil and *.dso.mil among other P1 branding. Keycloak is configurable to use your own theme. See the [Big Bang Keycloak repo documentation](https://repo1.dso.mil/big-bang/product/packages/keycloak/-/blob/main/development/README.md) for guidance on how to build and use your own custom theme with Keycloak.
The plugin is now available for public consumption in [Iron Bank](https://ironbank.dso.mil/repomap/details;registry1Path=big-bang%252Fp1-keycloak-plugin). The image registry path is `registry1.dso.mil/ironbank/big-bang/p1-keycloak-plugin:X.X.X`

# OCSP Authenticator Configuration

The plugin includes an OCSP (Online Certificate Status Protocol) authenticator that verifies the revocation status of X.509 certificates. To configure and use the OCSP authenticator:

1. Add the OCSP authenticator to your Keycloak authentication flow:
   - Log in to the Keycloak admin console
   - Navigate to Authentication > Flows
   - Select or create an authentication flow
   - Click "Add execution"
   - Select "Platform One OCSP Check" from the dropdown
   - Set the requirement to "REQUIRED"

2. Configure the OCSP authenticator using the following environment variables:

   ```
   KC_SPI_BABY_YODA_OCSP_ENABLED: "true"
   KC_SPI_BABY_YODA_OCSP_NONCE_IGNORE_LIST: "ocsp.northropgrumman.com,ocsp.external.lmco.com,ocsp.managed.entrust.com,eca.ocsp.identrust.com,ecas2.ocsp.identrust.com,ocsp.pki.va.gov,ocsp.treasury.gov,ocsp.dimc.dhs.gov"
   KC_SPI_BABY_YODA_OCSP_IGNORE_LIST: "ocsp.company.dso.mil"
   KC_SPI_BABY_YODA_OCSP_CACHE_ENABLED: "true"
   KC_SPI_BABY_YODA_OCSP_CACHE_TTL_HOURS: "23"
   ```

   - `KC_SPI_BABY_YODA_OCSP_ENABLED`: Enables the OCSP check in the authentication flow
   - `KC_SPI_BABY_YODA_OCSP_NONCE_IGNORE_LIST`: Comma-separated list of OCSP responders that should not use a nonce during OCSP requests
   - `KC_SPI_BABY_YODA_OCSP_IGNORE_LIST`: Comma-separated list of OCSP responders to completely ignore (mock as successful)
   - `KC_SPI_BABY_YODA_OCSP_CACHE_ENABLED`: Enables caching of OCSP results as user attributes
   - `KC_SPI_BABY_YODA_OCSP_CACHE_TTL_HOURS`: Time-to-live for cached OCSP results in hours

These settings can be configured in your Kubernetes deployment, Docker environment, or any other environment where Keycloak is running.

# Mattermost User Provisioning

The plugin includes an event listener that automatically provisions users in Mattermost upon email verification. This feature supports multiple environments (TEST, IL2, IL4, IL5) and can be configured via YAML.

## Configuration

1. Set the path to your YAML configuration file:
   ```
   CUSTOM_REGISTRATION_CONFIG: /opt/keycloak/conf/customreg.yaml
   ```

2. Set environment-specific provisioning tokens:
   ```
   MATTERMOST_TEST_PROVISION_TOKEN: pvt_xxxxx_test
   MATTERMOST_IL2_PROVISION_TOKEN: pvt_xxxxx_il2
   MATTERMOST_IL4_PROVISION_TOKEN: pvt_xxxxx_il4
   MATTERMOST_IL5_PROVISION_TOKEN: pvt_xxxxx_il5
   ```

3. Configure in your customreg.yaml:
   ```yaml
   mattermostProvisioning:
     enabled: true
     requestTimeoutSeconds: 30

     environments:
       TEST:
         enabled: true
         provisionUrl: "https://chat.test.dso.mil/plugins/auto-provision/provision"
         provisionToken: "${MATTERMOST_TEST_PROVISION_TOKEN}"
       IL2:
         enabled: true
         provisionUrl: "https://chat.il2.dso.mil/plugins/auto-provision/provision"
         provisionToken: "${MATTERMOST_IL2_PROVISION_TOKEN}"
       IL4:
         enabled: true
         provisionUrl: "https://chat.il4.dso.mil/plugins/auto-provision/provision"
         provisionToken: "${MATTERMOST_IL4_PROVISION_TOKEN}"
       IL5:
         enabled: false
         provisionUrl: "https://chat.il5.dso.mil/plugins/auto-provision/provision"
         provisionToken: "${MATTERMOST_IL5_PROVISION_TOKEN}"
   ```

4. Configure the persona attribute in User Profile:
   - Log in to Keycloak Admin Console
   - Select your realm
   - Navigate to Realm Settings → User Profile → Attributes
   - Create attribute with name `persona`, display name `Mattermost Access Code`
   - Set as optional, single-valued, user-metadata group
   - Grant edit/view permissions to User and Admin

5. Enable the event listener in your realm:
   - Log in to Keycloak Admin Console
   - Select your realm
   - Navigate to Events → Config
   - Add `mattermost-provisioning` to the Event Listeners field
   - Save the configuration

## Features

- **Multi-environment support**: Provisions users across TEST, IL2, IL4, and IL5 environments
- **Email verification required**: Only provisions after email is verified
- **Idempotency**: Prevents duplicate provisioning attempts
- **Partial failure handling**: Can succeed in some environments while failing in others
- **User attribute tracking**: Records provisioning status and environments

For detailed configuration and troubleshooting, see [docs/mattermost_provisioner/](docs/mattermost_provisioner/).

# Credits
Commit history could not be preserved. Credit goes to Jeff McCoy who developed the original plugin. The plugin is now maintained by Platform One.

# Additional Information
See more [docs](docs/). Be sure to review the [docs/compatibility-matrix.md](docs/compatibility-matrix.md) to choose the most appropriate version.

