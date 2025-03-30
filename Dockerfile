FROM eclipse-temurin:21-jre-alpine

ARG APP_NAME
ARG APP_VERSION

RUN test -n "$APP_NAME" || (echo "APP_NAME  not set" && false)
RUN test -n "$APP_VERSION" || (echo "APP_VERSION  not set" && false)

WORKDIR /app
COPY target/${APP_NAME}-${APP_VERSION}.jar /app/

EXPOSE 8080

ENV JAR_FILE_PATH="/app/${APP_NAME}-${APP_VERSION}.jar"
ENTRYPOINT ["sh", "-c", "java -jar ${JAR_FILE_PATH}"]