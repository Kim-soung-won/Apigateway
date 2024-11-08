package com.web.apigateway.api;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class LivenessController {
    @GetMapping("/health-check")
    public ResponseEntity<String> livenessProbe() {
        return ResponseEntity.ok("ok");
    }
}
