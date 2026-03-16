FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app

COPY backend/src/StealthBackend/pom.xml /app/pom.xml
COPY backend/src/StealthBackend/mvnw /app/mvnw
COPY backend/src/StealthBackend/mvnw.cmd /app/mvnw.cmd
COPY backend/src/StealthBackend/.mvn /app/.mvn

RUN chmod +x /app/mvnw && /app/mvnw -q -DskipTests dependency:go-offline

COPY backend/src/StealthBackend /app
RUN /app/mvnw -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app

RUN apt-get update && apt-get install -y python3 python3-pip curl && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/quarkus-app /app/quarkus-app
COPY backend/script /app/script

ENV QUARKUS_HTTP_HOST=0.0.0.0
ENV QUARKUS_HTTP_PORT=10000

EXPOSE 10000

CMD ["java", "-jar", "/app/quarkus-app/quarkus-run.jar"]
