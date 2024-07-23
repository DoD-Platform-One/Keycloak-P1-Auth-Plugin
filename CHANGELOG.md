# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
        //To Enable in command:  "--spi-baby-yoda-ocsp-enabled=true"
        //or in ENV:  KC_SPI_BABY_YODA_OCSP_ENABLED: "true"
        //KC_SPI_TRUSTSTORE_FILE_FILE: "/opt/keycloak/certs/truststore.jks"
        //KC_SPI_TRUSTSTORE_FILE_PASSWORD: "trust_pw"

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
