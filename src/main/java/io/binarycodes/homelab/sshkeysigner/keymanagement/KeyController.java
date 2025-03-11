package io.binarycodes.homelab.sshkeysigner.keymanagement;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;

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

    @PostMapping("/sign")
    public ResponseEntity<Boolean> upload(@RequestParam("file") MultipartFile multipartFile) {
        log.debug("Uploading file '" + multipartFile.getOriginalFilename() + "'");
        try {
            //File file = keyService.save(multipartFile);
            return ResponseEntity.ok().body(true);
        } catch (Exception e) {
            log.error("Error uploading file.", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
