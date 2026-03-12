package com.example.vulnerable;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@RestController
public class FileController {
    private static final String BASE_DIR = "/var/app/files/";

    @GetMapping("/file")
    public ResponseEntity<byte[]> getFile(@RequestParam String filename) throws IOException {
        File file = new File(BASE_DIR + filename);
        byte[] content = Files.readAllBytes(file.toPath());
        return ResponseEntity.ok(content);
    }
}
