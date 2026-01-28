ARG JAVA_VERSION="21"

FROM eclipse-temurin:${JAVA_VERSION}-jre-alpine

ARG APP_NAME
ARG APP_VERSION

RUN test -n "$APP_NAME" || (echo "APP_NAME  not set" && false) \
    && test -n "$APP_VERSION" || (echo "APP_VERSION  not set" && false)

RUN apk add --no-cache curl \
    && addgroup -S -g 10001 demo \
    && adduser -S -D -H -u 10001 -G demo demo

WORKDIR /app
COPY --chown=demo:demo target/${APP_NAME}-${APP_VERSION}.jar /app/app.jar

USER demo:demo
EXPOSE 8088

ENV JAVA_TOOL_OPTIONS="-XX:+ExitOnOutOfMemoryError -XX:MaxRAMPercentage=75"
ENTRYPOINT ["java","-jar","/app/app.jar"]

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=5 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8088/actuator/health/readiness"]
