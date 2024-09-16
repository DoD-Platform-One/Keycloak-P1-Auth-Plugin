ARG BASE_REGISTRY=registry1.dso.mil/ironbank
ARG BASE_IMAGE=redhat/ubi/ubi9-minimal
ARG BASE_TAG=9.4

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

WORKDIR /app

COPY build/libs/p1-keycloak-plugin*.jar /app/p1-keycloak-plugin.jar

# Create user / home directory for compliance
RUN microdnf upgrade -y && \
    microdnf clean all && \
    rm -rf /var/cache/yum /var/log/yum* && \
    groupadd -g 1000 bigbang && \
    useradd --uid 1000 -m -d /home/bigbang -s /sbin/nologin -g bigbang bigbang && \
    chmod 0750 /home/bigbang && \
    chmod +rx p1-keycloak-plugin*.jar

USER 1000:1000

HEALTHCHECK NONE
