package io.binarycodes.homelab.sshkeysigner.keymanagement;

import io.binarycodes.homelab.lib.SignPublicKeyRequest;
import io.binarycodes.homelab.lib.SignedPublicKeyDownload;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;

@Log4j2
@RestController
@RequestMapping("/rest/key")
public class KeyController {

    private final KeyService keyService;

    public KeyController(KeyService keyService) {
        this.keyService = keyService;
    }

    @PostMapping("/generate")
    public KeyInfo generateKey(@RequestParam String comment, @RequestParam String passphrase) {
        var key = keyService.generateKey(comment, passphrase);
        return key.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Key generation failed"));
    }

    @PostMapping("/userSign")
    public ResponseEntity<SignedPublicKeyDownload> signUserKey(JwtAuthenticationToken principal, @RequestBody SignPublicKeyRequest signPublicKeyRequest) {
        if (principal == null) {
            log.fatal("No principal. Refusing to sign certificate for \"{}\".", signPublicKeyRequest.principal());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .build();
        }

        if (!principal.getName()
                .equals(signPublicKeyRequest.principal())) {
            log.fatal("Invalid principal - \"{}\". Request and authorization do not match. Refusing to sign certificate for \"{}\".",
                    principal.getName(), signPublicKeyRequest.principal());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .build();
        }

        var signed = keyService.signUserKey(signPublicKeyRequest.filename(), signPublicKeyRequest.publicKey()
                .getBytes(StandardCharsets.UTF_8), signPublicKeyRequest.principal());

        return signed.map(signedPublicKeyDownload -> {
                    return ResponseEntity.ok()
                            .body(signedPublicKeyDownload);
                })
                .orElseGet(() -> ResponseEntity.badRequest()
                        .build());
    }

    @PostMapping("/hostSign")
    public ResponseEntity<SignedPublicKeyDownload> signHostKey(@RequestBody SignPublicKeyRequest signPublicKeyRequest) {
        var signed = keyService.signHostKey(signPublicKeyRequest.filename(), signPublicKeyRequest.publicKey()
                .getBytes(StandardCharsets.UTF_8), signPublicKeyRequest.principal());

        return signed.map(signedPublicKeyDownload -> {
                    return ResponseEntity.ok()
                            .body(signedPublicKeyDownload);
                })
                .orElseGet(() -> ResponseEntity.badRequest()
                        .build());
    }
}
