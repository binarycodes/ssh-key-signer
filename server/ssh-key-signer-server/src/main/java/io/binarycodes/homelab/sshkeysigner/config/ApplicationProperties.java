package io.binarycodes.homelab.sshkeysigner.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "app")
public record ApplicationProperties(
        @NotBlank
        String caUserPath,
        @NotBlank
        String caHostPath,
        Duration caUserValidity,
        Duration caHostValidity,
        List<String> sourceAddresses,
        List<String> knownExtensions
) {
}
