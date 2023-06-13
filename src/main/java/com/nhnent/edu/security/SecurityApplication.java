package com.nhnent.edu.security;

import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityApplication {
	@Bean
	public WebServerFactoryCustomizer<TomcatServletWebServerFactory> customizer(
		@Value("${server.http.port}") int httpPort) {
		return factory -> {
			final Connector connector = new Connector();
			connector.setPort(httpPort);
			factory.addAdditionalTomcatConnectors(connector);
		};
	}

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

}
