# EU DSS validator (docs/31 §7 rung 3, F-006). LGPL DSS stays in this image; nothing links it.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -o package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /src/target/eu-dss-validate-0.0.0.jar /app/validate.jar
COPY --from=build /src/target/lib /app/lib
ENTRYPOINT ["java", "-cp", "/app/validate.jar:/app/lib/*", "org.openseal.dss.Validate"]
