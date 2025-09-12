package io.binarycodes.homelab;

import io.binarycodes.homelab.lib.SignPublicKeyRequest;
import io.binarycodes.homelab.lib.SignedPublicKeyDownload;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

        ResponseEntity<SignedPublicKeyDownload> response = restClient.post()
                .uri("/rest/key/userSign")
                .contentType(MediaType.APPLICATION_JSON)
                .body(signPublicKeyRequest)
                .exchange((request, responseObj) -> {
                    var status = responseObj.getStatusCode();
                    if (status.is2xxSuccessful()) {
                        return ResponseEntity.ok(responseObj.bodyTo(SignedPublicKeyDownload.class));
                    } else {
                        return ResponseEntity.status(status)
                                .build();
                    }
                });

        if (response != null && response.getStatusCode()
                .is2xxSuccessful() && response.getBody() != null) {

            var signedPublicKeyDownload = response.getBody();

            var writeToPath = absolutePublicKeyPath.resolveSibling(signedPublicKeyDownload.filename());
            Files.writeString(writeToPath, signedPublicKeyDownload.signedKey());

            log.info("Key is signed and placed at - " + signedPublicKeyDownload.filename());
        } else {
            log.error("Error processing request - {}", response.getStatusCode()
                    .toString());
        }
    }

}
