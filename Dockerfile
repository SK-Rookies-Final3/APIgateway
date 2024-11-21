FROM openjdk:21-jdk
WORKDIR /app
COPY build/libs/*.jar app.jar

EXPOSE 8089

ENTRYPOINT ["java", "-jar", "app.jar"]
