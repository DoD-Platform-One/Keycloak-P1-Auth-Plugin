# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## [3.6.8] - 2025-4-21

### Updated

- Bumped support for Keycloak libraries to 26.2.0

## [3.6.7] - 2025-4-07

### Updated

- Bumped support for Keycloak libraries to 26.1.4

## [3.6.6] - 2025-3-28

### Updated

- Support for Keycloak 26.1.3
- New OCSP provider to replace Keycloaks built in ocsp provider as part of the x509 auth flow. This allows disabling nonce for specific OCSP providers as well as skipping OCSP checking completely for whitelisted providers.
  - Configure with environment variables:
    ```
    KC_SPI_BABY_YODA_OCSP_ENABLED: "true"
    KC_SPI_BABY_YODA_OCSP_NONCE_IGNORE_LIST: "ocsp.northropgrumman.com,ocsp.external.lmco.com,ocsp.managed.entrust.com,eca.ocsp.identrust.com,ecas2.ocsp.identrust.com,ocsp.pki.va.gov,ocsp.treasury.gov,ocsp.dimc.dhs.gov"
    KC_SPI_BABY_YODA_OCSP_IGNORE_LIST: "ocsp.example.mil"
    KC_SPI_BABY_YODA_OCSP_CACHE_ENABLED: "true"
    KC_SPI_BABY_YODA_OCSP_CACHE_TTL_HOURS: "23"
    ```
  - See README.md for detailed configuration instructions.
- UpdateX509 Required Action now pulls various attributes off PIV and stores as user attributes.
- Test Coverage has been updated from JUnit4 to JUnit5 and from PowerMockito to Mockito.
- Cleaned up all Sonarqube issues. Rewrote a lot of code to address complexity and duplication errors.
- Increased Test Coverage across all files by roughly 800 new tests.
- Optimized gradle build to run faster.
- Created a new WelcomeEmail Event Listener which sends a custom email to all new users. Currently template is hardcoded in plugin but next release will have a configuration file or variable to pull content from.

## [3.5.8] - 2024-10-08

### Updated

- Removed left over TCODE reference in the themes file (keycloak-themes.json)
- Updated RegistrationValidation.java to only allow baby-yoda realm to use autoJoinGroup feature.
  - This method was causing issues with other realms, the proper fix will come in a later release.
- Update tests to adapt to changes in RegistrationValidation.java
- Removed the auto-population of username and made the field editable.
- Added back email confirmation during registration to CAC users.


## [3.5.7] - 2024-10-02

### Updated

- Bumped version of Keycloak libraries to 25.0.6

## [3.5.6] - 2024-09-16

### Updated

- Bumped version of Keycloak libraries to 25.0.4

## [3.5.5] - 2024-09-16

### Updated

- Update Dockerfile with microdnf commands

## [3.5.4] - 2024-08-27

### Updated

- Registration form updates include:
  - Reading of First Name, Last Name, Affiliation from CAC card and auto population of them
  - UI restriction of email domains to gov and business emails
  - UI restriction of password requirements
  - UI disablement of password confirmation until password field passes requirements check
  - Appearance of username field once the entered email contains '@' sign and disappearance if it is removed.
  - Auto-population of username with email prefix(all chars preceeding '@' sign)

## [3.5.3] - 2024-08-23

### Updated

- Update all email references to help@dsop.io email in P1-SSO theme

## [3.5.2] - 2024-08-12

### Updated

- Update help@dsop.io email in P1-SSO theme
- Added email confirmation field in registration page
- Multi-Realm now supported
-        // Need to update this fields because of KC 25 update
         // KC_HOSTNAME: "https://<YOUR HOSTNAME>/auth"
         // KC_HOSTNAME_ADMIN: "https://<YOUR ADMIN HOSTNAME>/auth"

-        // This field is required for the plugin to support multiple realms
         // KC_SPI_MULTI_REALM_ENABLED: "true"

## [3.5.1] - 2024-07-22

### Updated

- Bumped version of Keycloak libraries to 25.0.2

## [3.5.0] - 2024-06-28

### Updated

- Bumped version of Keycloak libraries to 25.0.1
- Fixed code and unit tests broken by increased version
- Update to use Java21
- Fix theme warning

## [3.4.0] - 2024-06-20

### Updated

- Bumped version of Keycloak libraries to 24.0.5
- Fixed code and unit tests broken by increased version

## [3.3.3] - 2024-05-22

### Updated

- Added Confluence instructions on how to create a new Theme. Also refactor the current Theme with the
  new way since it is kind of generic enough for other Realms to use the Theme.
- Updated Theme, it is more dynamic, not longer hardcoded to baby-yoda.
- Updated Snakeyml dependency to 2.2, requested by cyber. Vulnerability fixed.
- Mobile rendering update, now it should display readable in a mobile device.
- OCSP refactor, now a flag needs to be updated in order to be used. By default it is off.
-       // OCSP Check to address revoked cert getting activecac attribute.
        // To Enable in command:  "--spi-baby-yoda-ocsp-enabled=true"
        // or in ENV:  KC_SPI_BABY_YODA_OCSP_ENABLED: "true"
        // KC_SPI_TRUSTSTORE_FILE_FILE: "/opt/keycloak/certs/truststore.jks"
        // KC_SPI_TRUSTSTORE_FILE_PASSWORD: "trust_pw"

## [3.3.2] - 2024-05-03

### Updated

- [Style optimizations to better support mobile browsers](https://repo1.dso.mil/big-bang/product/plugins/keycloak-p1-auth-plugin/-/issues/27).
- Updated Dockerfile to match that of [the Iron Bank version](https://repo1.dso.mil/dsop/big-bang/p1-keycloak-plugin/-/blob/master/Dockerfile?ref_type=heads).

## [3.3.1] - 2023-11-17

### Updated

- Upgrade Jacoco to version 0.8.11
  1. Replace deprecated methods in build.gradle with the current method
  2. Remove JacocoMerge
  3. Added JacocoReport
- Upgrade gradle to version 8.4
- Update gradle wrapper version from 7.6.3 to 8.4
- Upgraded Lombok to version 8.4
- Upgraded io.quarkus to version 3.5.2
- Upgraded jakarta.enterprise to 4.0.0
- Upgraded jakarta.inject to 2.0.1

## [3.3.0] - 2023-09-06

### Updated

- Upgrade Keycloak libraries to version 23.0.0
- Updated imports to be compatible with 23.0.X libraries
  1. Add dependency 'javax.enterprise:cdi-api:1.2' to maven and gradle to address error 'package javax.enterprise.context does not exist' in quarkus-ext-routing/runtime and in quarkus-ext-routing/deployment
  2. Changed javax to Jakarta in p1-keycloak-plugin build.gradle to address 'incompatible types: ... cannot be converted to javax.ws.rs.core..."
- Update java version from 11 to 17
- Update gradle wrapper version from 7.4.2 to 7.6.3
- Updated dependency org.owasp:dependency-check-gradle from 7.2.1 to 8.4.0
- Bump base image in Dockerfile from ubi8.8 to 9.2
- Add new plugin code to bring back Theme V1 compatible

## [3.2.1] - 2023-05-02

### Updated

- Fix bug with health/metrics endpoint blocking
- Fix bug with Terms of Agreement existing database records
- Update Terms of Agreement

## [3.2.0] - 2023-03-06

### Updated

- Upgrade Keycloak libraries to version 21.0.2

## [3.1.0] - 2023-02-03

### Added

- Added custum quarkus extension feature that is configurable to block /metrics and /health endpoints from being exposed through ingress.
- Added compatibility matrix documentation

## [3.0.1] - 2023-01-25

### Updated

- Upgrade Keycloak libraries to version 20.0.3
- Update documentation

## [3.0.0] - 2022-12-13

### Updated

- Upgrade Keycloak to version 20.0.1

### Added

- Added Quarkus custom extension for  Routing

## [2.0.10] - 2022-08-11

### Updated

- Fix sonar findings

## [2.0.9] - 2022-08-09

### Updated

- Upgrade Keycloak to version 19.0.1

## [2.0.8] - 2022-08-07

### Updated

- more unit tests
- add private constructor to NewObjectProvider to satisfy sonar scan.

## [2.0.7] - 2022-08-04

### Updated

- more unit tests

## [2.0.6] - 2022-08-02

### Updated

- unit tests
- documentation
- lombok gradle plugin upgrade to 6.5.0.3

### Added

- x509.sh script

## [2.0.5] - 2022-07-05

### Updated

- more Sonarqube remediation

## [2.0.4] - 2022-07-01

### Updated

- Remediate dependency check findings
- Upgrade to Keycloak 18.0.2

## [2.0.3] - 2022-06-30

### Updated

- Sonarqube remediation

## [2.0.2] - 2022-06-29

### Updated

- Fortify remediation

## [2.0.1] - 2022-06-29

### Updated

- Linting

## [2.0.0] - 2022-06-22

### Updated

- Initial code
