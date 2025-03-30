package io.binarycodes.homelab.sshkeysigner.keymanagement;

import lombok.extern.log4j.Log4j2;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

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

    @PostMapping("/userSign")
    public ResponseEntity<ByteArrayResource> signUserKey(@RequestParam("file") MultipartFile multipartFile) {
        log.debug("Uploading file '" + multipartFile.getOriginalFilename() + "'");
        try {
            var signed = keyService.signUserKey(multipartFile.getOriginalFilename(), multipartFile.getBytes());

            return signed.map(signedPublicKeyDownload -> {
                var httpHeaders = new HttpHeaders();
                httpHeaders.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + signedPublicKeyDownload.filename());
                httpHeaders.add("Cache-Control", "no-cache, no-store, must-revalidate");
                httpHeaders.add("Pragma", "no-cache");
                httpHeaders.add("Expires", "0");

                var resource = new ByteArrayResource(signedPublicKeyDownload.signedKey());

                return ResponseEntity.ok().headers(httpHeaders).contentLength(signedPublicKeyDownload.signedKey().length).contentType(MediaType.APPLICATION_OCTET_STREAM).body(resource);
            }).orElseGet(() -> ResponseEntity.badRequest().build());
        } catch (Exception e) {
            log.error("Error uploading file.", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/hostSign")
    public ResponseEntity<ByteArrayResource> signHostKey(@RequestParam("file") MultipartFile multipartFile) {
        log.debug("Uploading file '" + multipartFile.getOriginalFilename() + "'");
        try {
            var signed = keyService.signUserKey(multipartFile.getOriginalFilename(), multipartFile.getBytes());

            return signed.map(signedPublicKeyDownload -> {
                var httpHeaders = new HttpHeaders();
                httpHeaders.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + signedPublicKeyDownload.filename());
                httpHeaders.add("Cache-Control", "no-cache, no-store, must-revalidate");
                httpHeaders.add("Pragma", "no-cache");
                httpHeaders.add("Expires", "0");

                var resource = new ByteArrayResource(signedPublicKeyDownload.signedKey());

                return ResponseEntity.ok().headers(httpHeaders).contentLength(signedPublicKeyDownload.signedKey().length).contentType(MediaType.APPLICATION_OCTET_STREAM).body(resource);
            }).orElseGet(() -> ResponseEntity.badRequest().build());
        } catch (Exception e) {
            log.error("Error uploading file.", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
