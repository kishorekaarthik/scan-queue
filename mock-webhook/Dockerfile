FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY target/mock-webhook.jar app.jar
USER app
ENV JAVA_TOOL_OPTIONS="-Xms32m -Xmx128m -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -Xss512k -XX:MaxMetaspaceSize=128m"
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
