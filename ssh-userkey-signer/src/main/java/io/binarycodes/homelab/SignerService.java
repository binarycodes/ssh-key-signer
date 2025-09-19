package io.binarycodes.homelab;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import io.binarycodes.homelab.lib.SignPublicKeyRequest;
import io.binarycodes.homelab.lib.SignedPublicKeyDownload;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Log4j2
@Service
public class SignerService {
    private final ApplicationProperties applicationProperties;

    @Autowired
    public SignerService(final ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    public void signMyKey(final String token, final String publicKeyFilePath, final String principalName) throws IOException {
        final var absolutePublicKeyPath = Path.of(publicKeyFilePath)
                .toAbsolutePath();

        final var fileName = absolutePublicKeyPath.getFileName()
                .toString();
        final var publicKey = Files.readString(absolutePublicKeyPath);

        final var signPublicKeyRequest = new SignPublicKeyRequest(fileName, publicKey, principalName);

        final var restClient = RestClient.builder()
                .baseUrl(applicationProperties.serverUrl())
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(token))
                .build();
 
        final ResponseEntity<SignedPublicKeyDownload> response = restClient.post()
                .uri("/rest/key/userSign")
                .contentType(MediaType.APPLICATION_JSON)
                .body(signPublicKeyRequest)
                .exchange((request, responseObj) -> {
                    final var status = responseObj.getStatusCode();
                    if (status.is2xxSuccessful()) {
                        return ResponseEntity.ok(responseObj.bodyTo(SignedPublicKeyDownload.class));
                    } else {
                        return ResponseEntity.status(status)
                                .build();
                    }
                });

        if (response != null && response.getStatusCode()
                .is2xxSuccessful() && response.getBody() != null) {

            final var signedPublicKeyDownload = response.getBody();

            final var writeToPath = absolutePublicKeyPath.resolveSibling(signedPublicKeyDownload.filename());
            Files.writeString(writeToPath, signedPublicKeyDownload.signedKey());

            log.info("Key is signed and placed at - " + signedPublicKeyDownload.filename());
        } else {
            log.error("Error processing request - {}", response.getStatusCode()
                    .toString());
        }
    }

}
