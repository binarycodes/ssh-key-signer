package io.binarycodes.homelab.sshkeysigner.keymanagement;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/rest/key")
public class KeyController {

    private final KeyService keyService;

    public KeyController(KeyService keyService) {
        this.keyService = keyService;
    }

    @GetMapping("test")
    public String test() {
        return "Hello world!";
    }

    @PostMapping("generate")
    public KeyInfo generateKey(@RequestParam String comment, @RequestParam String passphrase) {
        var key = keyService.generateKey(comment, passphrase);
        return key.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Key generation failed"));
    }
}
