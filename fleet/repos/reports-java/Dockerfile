# Plain javac build against the vendored jars in lib/. No Maven, no network.
FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY lib/ lib/
COPY src/ src/
RUN javac -cp "lib/*" -d classes $(find src -name '*.java')

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /src/classes classes/
COPY resources/ classes/
COPY lib/ lib/
EXPOSE 8080
CMD ["java", "-cp", "classes:lib/*", "reports.Job"]
