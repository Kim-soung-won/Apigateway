package com.web.apigateway.service;

import com.web.apigateway.exception.RecordException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CircuitBreakerService {

    @CircuitBreaker(name = "AuthService", fallbackMethod = "fallbackAuthService")
    public String authClientError(String message){
        throw new RecordException(message);
    }

    private String fallbackAuthService(RecordException e){
        log.error("[Auth Service Error] callFallback {}", e.getMessage());
        return e.getMessage();
    }
}
