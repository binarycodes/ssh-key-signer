package io.binarycodes.homelab.sshkeysigner.keymanagement;

import java.nio.charset.StandardCharsets;

import io.binarycodes.homelab.lib.SignPublicKeyRequest;
import io.binarycodes.homelab.lib.SignedPublicKeyDownload;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@Log4j2
@RestController
@RequestMapping("/rest/key")
public class KeyController {

    private final KeyService keyService;

    public KeyController(final KeyService keyService) {
        this.keyService = keyService;
    }

    @PostMapping("/generate")
    public KeyInfo generateKey(@RequestParam final String comment, @RequestParam final String passphrase) {
        final var key = keyService.generateKey(comment, passphrase);
        return key.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Key generation failed"));
    }

    @PostMapping("/userSign")
    public ResponseEntity<SignedPublicKeyDownload> signUserKey(final JwtAuthenticationToken principal, @RequestBody final SignPublicKeyRequest signPublicKeyRequest) {
        final var validationOk = validateAuthentication(principal, signPublicKeyRequest);
        if (!validationOk) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .build();
        }

        final var signed = keyService.signUserKey(signPublicKeyRequest.filename(), signPublicKeyRequest.publicKey()
                .getBytes(StandardCharsets.UTF_8), signPublicKeyRequest.principal());

        return signed.map(signedPublicKeyDownload -> {
                    return ResponseEntity.ok()
                            .body(signedPublicKeyDownload);
                })
                .orElseGet(() -> ResponseEntity.badRequest()
                        .build());
    }

    @PostMapping("/hostSign")
    public ResponseEntity<SignedPublicKeyDownload> signHostKey(final JwtAuthenticationToken principal, @RequestBody final SignPublicKeyRequest signPublicKeyRequest) {
        final var validationOk = validateAuthentication(principal, signPublicKeyRequest);
        if (!validationOk) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .build();
        }

        final var signed = keyService.signHostKey(signPublicKeyRequest.filename(), signPublicKeyRequest.publicKey()
                .getBytes(StandardCharsets.UTF_8), signPublicKeyRequest.principal());

        return signed.map(signedPublicKeyDownload -> {
                    return ResponseEntity.ok()
                            .body(signedPublicKeyDownload);
                })
                .orElseGet(() -> ResponseEntity.badRequest()
                        .build());
    }

    private boolean validateAuthentication(final JwtAuthenticationToken principal, final SignPublicKeyRequest signPublicKeyRequest) {
        if (principal == null) {
            log.fatal("No principal. Refusing to sign certificate for \"{}\".", signPublicKeyRequest.principal());
            return false;
        }

        if (principal.getName() == null) {
            log.fatal("No principal name. Refusing to sign certificate for \"{}\".", signPublicKeyRequest.principal());
            return false;
        }

        if (!principal.getName()
                .equals(signPublicKeyRequest.principal())) {
            log.fatal("Invalid principal - \"{}\". Request and authorization do not match. Refusing to sign certificate for \"{}\".",
                    principal.getName(), signPublicKeyRequest.principal());

            return false;
        }
        return true;
    }
}
