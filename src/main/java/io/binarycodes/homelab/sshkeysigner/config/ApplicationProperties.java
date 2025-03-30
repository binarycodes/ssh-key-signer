package io.binarycodes.homelab.sshkeysigner.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record ApplicationProperties(
        String caUserPath,
        String caHostPath
) {
}
