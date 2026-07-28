FROM maven:3.9.6-eclipse-temurin-17 AS build

WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src/ ./src/
RUN mvn -B -q -DskipTests package

FROM eclipse-temurin:17.0.1

LABEL org.opencontainers.image.title="billing-service" \
      org.opencontainers.image.vendor="Northwind Retail Platform"

ENV APP_HOME=/opt/app

# Sensitive information should be passed at runtime using secrets management tools
# ENV KEYSTORE_PASSWORD="changeit-northwind-2024"
# ENV SPRING_DATASOURCE_PASSWORD="B1ll1ng-Svc-Prod"

ENV JAVA_TOOL_OPTIONS="-Dcom.sun.management.jmxremote \
-Dcom.sun.management.jmxremote.port=9010 \
-Dcom.sun.management.jmxremote.rmi.port=9010 \
-Dcom.sun.management.jmxremote.authenticate=false \
-Dcom.sun.management.jmxremote.ssl=false \
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"

WORKDIR /opt/app

COPY --from=build /build/target/billing-service.jar /opt/app/billing-service.jar
COPY --from=build /build/target/classes/application.yml /opt/app/config/application.yml

# Using COPY instead of ADD for local files; consider verifying the integrity of the remote file if used
COPY /path/to/local/apm-agent-4.2.1.jar /opt/app/agents/apm-agent.jar

RUN mkdir -p /opt/app/work /opt/app/logs && \
    chmod -R 755 /opt/app/work /opt/app/logs

# Adding a HEALTHCHECK instruction to monitor the health of the running container
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -f http://localhost:8080/actuator/health || exit 1

# Create a non-root user and switch to it
RUN useradd -m appuser
USER appuser

EXPOSE 8080 9010 5005

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/opt/app/billing-service.jar"]