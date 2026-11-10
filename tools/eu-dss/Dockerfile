# EU DSS validator (docs/31 §7 rung 3, F-006). LGPL DSS stays in this image; nothing links it.
# Base images pinned by digest: a floating tag let Java 21.0.13 into the image on 2026-11-11,
# and EU DSS then failed to compute an Ed448/SHAKE256 digest it computed before (DSS-01).
FROM maven:3.9.16-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -o package -DskipTests

FROM eclipse-temurin:21.0.12.1_1-jre@sha256:f37956012e0cb88400e5b3689aeae2d2d735364c1922ae2225536163b5a99f56
WORKDIR /app
COPY --from=build /src/target/eu-dss-validate-0.0.0.jar /app/validate.jar
COPY --from=build /src/target/lib /app/lib
ENTRYPOINT ["java", "-cp", "/app/validate.jar:/app/lib/*", "org.openseal.dss.Validate"]
