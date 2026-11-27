FROM eclipse-temurin:25-jdk AS build
WORKDIR /app
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN ./mvnw -q dependency:go-offline
COPY src src
RUN ./mvnw -q -DskipTests package

FROM eclipse-temurin:25-jre
RUN useradd --system --no-create-home --uid 10001 app
WORKDIR /app
COPY --from=build /app/target/java-ed25519-example-0.0.1-SNAPSHOT.jar app.jar
USER app
EXPOSE 8080
CMD ["java", "-XX:+UseZGC", "-jar", "app.jar"]
