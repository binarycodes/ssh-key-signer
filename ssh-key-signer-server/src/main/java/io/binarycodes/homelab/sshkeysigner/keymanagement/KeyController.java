package io.binarycodes.homelab.sshkeysigner.keymanagement;

import lombok.extern.log4j.Log4j2;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.Principal;

@Log4j2
@RestController
@RequestMapping("/rest/key")
public class KeyController {

    private final KeyService keyService;

    public KeyController(KeyService keyService) {
        this.keyService = keyService;
    }

    @PostMapping("generate")
    public KeyInfo generateKey(@RequestParam String comment, @RequestParam String passphrase) {
        var key = keyService.generateKey(comment, passphrase);
        return key.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Key generation failed"));
    }

    @PostMapping("/upload")
    public ResponseEntity<ByteArrayResource> upload(@RequestParam("file") MultipartFile multipartFile) {
        log.debug("Uploading file '" + multipartFile.getOriginalFilename() + "'");
        return ResponseEntity.ok().build();
    }


    @PostMapping("/userSign")
    public ResponseEntity<SignedPublicKeyDownload> signUserKey(@AuthenticationPrincipal Principal principal, @RequestBody SignedPublicKeyRequest signedPublicKeyRequest) {
        var signed = keyService.signUserKey(signedPublicKeyRequest.filename(), signedPublicKeyRequest.publicKey().getBytes(StandardCharsets.UTF_8), signedPublicKeyRequest.data());

        return signed.map(signedPublicKeyDownload -> {
            return ResponseEntity.ok().body(signedPublicKeyDownload);
        }).orElseGet(() -> ResponseEntity.badRequest().build());
    }

    @PostMapping("/hostSign")
    public ResponseEntity<SignedPublicKeyDownload> signHostKey(@AuthenticationPrincipal Principal principal, @RequestBody SignedPublicKeyRequest signedPublicKeyRequest) {
        var signed = keyService.signHostKey(signedPublicKeyRequest.filename(), signedPublicKeyRequest.publicKey().getBytes(StandardCharsets.UTF_8), signedPublicKeyRequest.data());

        return signed.map(signedPublicKeyDownload -> {
            return ResponseEntity.ok().body(signedPublicKeyDownload);
        }).orElseGet(() -> ResponseEntity.badRequest().build());
    }
}
