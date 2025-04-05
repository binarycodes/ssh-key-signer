package io.binarycodes.homelab;

import lombok.extern.log4j.Log4j2;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.io.IOException;

@Log4j2
@SpringBootApplication
@ConfigurationPropertiesScan
public class SpringBootConsoleApplication implements CommandLineRunner {
    private final SignerService signerService;
    private final AuthService authService;

    public SpringBootConsoleApplication(SignerService signerService, AuthService authService) {
        this.signerService = signerService;
        this.authService = authService;
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringBootConsoleApplication.class, args);
    }

    @Override
    public void run(String... args) {
        var tokenResponse = authService.fetchAuthToken();
        tokenResponse.ifPresentOrElse(token -> {
            try {
                signerService.signMyKey(token, args[0], args[1]);
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
        }, () -> {
            log.error("Error getting auth token.");
        });

    }
}