package io.binarycodes.homelab;

import io.binarycodes.homelab.lib.SignPublicKeyRequest;
import io.binarycodes.homelab.lib.SignedPublicKeyDownload;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Log4j2
@Service
public class SignerService {
    private final ApplicationProperties applicationProperties;

    @Autowired
    public SignerService(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    public void signMyKey(String token, String publicKeyFilePath, String principalName) throws IOException {
        var absolutePublicKeyPath = Path.of(publicKeyFilePath)
                .toAbsolutePath();

        var fileName = absolutePublicKeyPath.getFileName()
                .toString();
        var publicKey = Files.readString(absolutePublicKeyPath);

        var signPublicKeyRequest = new SignPublicKeyRequest(fileName, publicKey, principalName);

        var restClient = RestClient.builder()
                .baseUrl(applicationProperties.serverUrl())
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(token))
                .build();

        var response = restClient.post()
                .uri("/rest/key/hostSign")
                .contentType(MediaType.APPLICATION_JSON)
                .body(signPublicKeyRequest)
                .retrieve()
                .toEntity(SignedPublicKeyDownload.class);

        var signedPublicKeyDownload = response.getBody();
        if (response.getStatusCode()
                .is2xxSuccessful() && signedPublicKeyDownload != null) {

            var writeToPath = absolutePublicKeyPath.resolveSibling(signedPublicKeyDownload.filename());
            Files.writeString(writeToPath, signedPublicKeyDownload.signedKey());

            log.info("Key is signed and placed at - " + signedPublicKeyDownload.filename());
        } else {
            log.error("Error processing request");
            log.error(response.getStatusCode()
                    .getClass());
        }
    }

}
