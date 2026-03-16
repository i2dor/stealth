FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app

COPY pom.xml mvnw mvnw.cmd ./
COPY .mvn ./.mvn
RUN chmod +x mvnw && ./mvnw -q -DskipTests dependency:go-offline

COPY . .
RUN ./mvnw -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app

RUN apt-get update && apt-get install -y python3 python3-pip curl && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/quarkus-app /app/quarkus-app
COPY ../../../script /app/script

ENV QUARKUS_HTTP_HOST=0.0.0.0
ENV QUARKUS_HTTP_PORT=10000
EXPOSE 10000

CMD ["java", "-jar", "/app/quarkus-app/quarkus-run.jar"]
