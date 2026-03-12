package com.example.safe;

import org.apache.commons.io.FilenameUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@RestController
public class SafeFileController {
    private static final String BASE_DIR = "/var/app/files/";

    @GetMapping("/safe/file")
    public ResponseEntity<byte[]> getFile(@RequestParam String filename) throws IOException {
        String safeFilename = FilenameUtils.getName(filename);
        File file = new File(BASE_DIR + safeFilename);
        if (!file.getCanonicalPath().startsWith(BASE_DIR)) {
            throw new SecurityException("Access denied");
        }
        byte[] content = Files.readAllBytes(file.toPath());
        return ResponseEntity.ok(content);
    }
}
