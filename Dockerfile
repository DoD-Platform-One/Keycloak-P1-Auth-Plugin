FROM registry1.dso.mil/ironbank/redhat/ubi/ubi8-minimal:8.6

RUN mkdir /app

WORKDIR /app

COPY build/libs/p1-keycloak-plugin-*.jar /app

RUN chmod -R +rx /app
