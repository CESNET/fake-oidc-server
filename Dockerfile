FROM eclipse-temurin:17-jre
RUN useradd -ms /bin/bash user
WORKDIR /usr/local/bin/user

COPY target/fake_oidc_server.jar oidc.jar
RUN chmod 777 oidc.jar
USER user
EXPOSE 8090
CMD ["java", "-jar", "-Dspring.profiles.active=default", "oidc.jar"] 
