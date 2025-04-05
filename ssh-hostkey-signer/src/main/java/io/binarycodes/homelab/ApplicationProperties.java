package io.binarycodes.homelab;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record ApplicationProperties(String serverUrl,
                                    String keycloakUrl,
                                    String realmName,
                                    String clientId,
                                    String clientSecret,
                                    String grantType,
                                    String tokenUrl) {
}
