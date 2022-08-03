FROM registry1.dso.mil/ironbank/redhat/ubi/ubi8-minimal:8.6

RUN mkdir /app

WORKDIR /app

COPY build/libs/platform-one-sso-*.jar /app
COPY x509.sh /app

RUN chmod -R +rx /app
