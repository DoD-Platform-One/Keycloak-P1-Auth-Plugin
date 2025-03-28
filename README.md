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

# Credits
Commit history could not be preserved. Credit goes to Jeff McCoy who developed the original plugin. The plugin is now maintained by Platform One.

# Additional Information
See more [docs](docs/). Be sure to review the [docs/compatibility-matrix.md](docs/compatibility-matrix.md) to choose the most appropriate version.