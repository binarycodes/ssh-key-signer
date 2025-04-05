package io.binarycodes.homelab;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.binarycodes.homelab.lib.DeviceFlowStartResponse;
import io.binarycodes.homelab.lib.DeviceFlowToken;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import pro.leaco.console.qrcode.ConsoleQrcode;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Log4j2
@Service
public class AuthService {
    private final ApplicationProperties applicationProperties;

    @Autowired
    public AuthService(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    public Optional<String> startDeviceFlowAuth() {
        return initiateDeviceFlow().map(this::displayLoginInfo)
                .flatMap(this::waitForToken);
    }

    private RestClient getRestClient() {
        return RestClient.builder()
                .baseUrl(applicationProperties.keycloakUrl())
                .build();
    }

    private DeviceFlowStartResponse displayLoginInfo(DeviceFlowStartResponse deviceFlowStartResponse) {
        System.out.println(deviceFlowStartResponse.getVerificationUriComplete());

        var qrCode = ConsoleQrcode.INSTANCE.generateUnicodeQrcode(deviceFlowStartResponse.getVerificationUriComplete());
        System.out.println(qrCode);

        return deviceFlowStartResponse;
    }

    private Optional<String> waitForToken(DeviceFlowStartResponse deviceFlowStartResponse) {
        try {
            var token = CompletableFuture.supplyAsync(() -> pollForToken(deviceFlowStartResponse))
                    .get(deviceFlowStartResponse.getExpiresIn(), TimeUnit.SECONDS);
            return Optional.of(token);
        } catch (TimeoutException | InterruptedException | ExecutionException e) {
            log.error(e.getMessage(), e);
        }
        return Optional.empty();
    }

    private String pollForToken(DeviceFlowStartResponse deviceFlowStartResponse) {
        var authToken = fetchAuthToken(deviceFlowStartResponse);

        if (authToken.isPresent()) {
            return authToken.get();
        }

        try {
            Thread.sleep(deviceFlowStartResponse.getInterval() * 1000L);
        } catch (InterruptedException e) {
            log.error(e.getMessage(), e);
            return null;
        }
        return pollForToken(deviceFlowStartResponse);
    }

    private Optional<String> fetchAuthToken(DeviceFlowStartResponse deviceFlowStartResponse) {
        var paramMap = new LinkedMultiValueMap<>();
        paramMap.add("client_id", applicationProperties.clientId());
        paramMap.add("client_secret", applicationProperties.clientSecret());
        paramMap.add("grant_type", applicationProperties.deviceGrantType());
        paramMap.add("device_code", deviceFlowStartResponse.getDeviceCode());

        var response = getRestClient().post()
                .uri(applicationProperties.tokenPollUrl())
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

    private Optional<DeviceFlowStartResponse> initiateDeviceFlow() {
        var paramMap = new LinkedMultiValueMap<>();
        paramMap.add("client_id", applicationProperties.clientId());
        paramMap.add("client_secret", applicationProperties.clientSecret());
        paramMap.add("scope", applicationProperties.deviceScope());

        var response = getRestClient().post()
                .uri(applicationProperties.startDeviceFlowUrl())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(paramMap)
                .retrieve()
                .toEntity(String.class);

        if (!response.getStatusCode()
                .is2xxSuccessful()) {
            return Optional.empty();
        }

        try {
            var deviceFlowStartResponse = new ObjectMapper().readValue(response.getBody(), DeviceFlowStartResponse.class);
            return Optional.ofNullable(deviceFlowStartResponse);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
        }

        return Optional.empty();
    }
}
