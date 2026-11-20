# The jar is built on the host (./mvnw package) so image builds stay fast and light.
# One image serves every role; the role is chosen with SPRING_PROFILES_ACTIVE.
FROM eclipse-temurin:21-jre-alpine

# YARA CLI for the worker role (phase 2). Small, and harmless for other roles.
RUN apk add --no-cache yara \
 && addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY target/scanner-app.jar app.jar
USER app

# Small heap + Serial GC: many of these JVMs run side by side on a laptop.
ENV JAVA_TOOL_OPTIONS="-Xms32m -Xmx160m -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -Xss512k -XX:MaxMetaspaceSize=128m"
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
