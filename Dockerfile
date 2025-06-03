FROM eclipse-temurin:17-jdk-alpine
RUN addgroup -S appgrp && \
    adduser -S appuser -G appgrp
WORKDIR /app
COPY target/alertachuva-api-0.0.1-SNAPSHOT.jar app.jar
ENV SPRING_PROFILES_ACTIVE=prod
EXPOSE 8080
USER appuser
ENTRYPOINT ["java", "-jar", "app.jar"]
