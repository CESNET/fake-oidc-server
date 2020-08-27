package cz.metacentrum.fake_oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class FakeOidcServer {

	public static void main(String[] args) {
		SpringApplication.run(FakeOidcServer.class, args);
	}

}
