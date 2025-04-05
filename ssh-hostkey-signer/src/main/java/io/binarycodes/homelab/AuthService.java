package io.binarycodes.homelab;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.binarycodes.homelab.lib.DeviceFlowToken;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Log4j2
@Service
public class AuthService {
    private final ApplicationProperties applicationProperties;

    @Autowired
    public AuthService(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    private RestClient getRestClient() {
        return RestClient.builder()
                .baseUrl(applicationProperties.keycloakUrl())
                .build();
    }

    public Optional<String> fetchAuthToken() {
        var paramMap = new LinkedMultiValueMap<>();
        paramMap.add("client_id", applicationProperties.clientId());
        paramMap.add("client_secret", applicationProperties.clientSecret());
        paramMap.add("grant_type", applicationProperties.grantType());

        var response = getRestClient().post()
                .uri(applicationProperties.tokenUrl())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(paramMap)
                .retrieve()
                .onStatus(status -> !status.is2xxSuccessful(), (httpRequest, httpResponse) -> {
                    var errorResponse = new String(httpResponse.getBody()
                            .readAllBytes(), StandardCharsets.UTF_8);
                    log.debug(errorResponse);
                })
                .toEntity(String.class);

        if (!response.getStatusCode()
                .is2xxSuccessful()) {
            return Optional.empty();
        }

        try {
            var accessTokenResponse = new ObjectMapper().readValue(response.getBody(), DeviceFlowToken.class);
            return Optional.ofNullable(accessTokenResponse.getAccessToken());
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
        }

        return Optional.empty();
    }
}
