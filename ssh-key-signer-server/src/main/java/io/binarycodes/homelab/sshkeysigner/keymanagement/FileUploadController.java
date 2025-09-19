package io.binarycodes.homelab.sshkeysigner.keymanagement;

import lombok.extern.log4j.Log4j2;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@Log4j2
@RestController
@RequestMapping("/rest/upload")
public class FileUploadController {

    @PostMapping("/file")
    public ResponseEntity<ByteArrayResource> upload(@RequestParam("file") final MultipartFile multipartFile) {
        log.debug("Uploading file '" + multipartFile.getOriginalFilename() + "'");
        return ResponseEntity.ok()
                .build();
    }
}
