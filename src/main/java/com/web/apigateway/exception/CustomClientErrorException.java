package com.web.apigateway.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class CustomClientErrorException extends RuntimeException {
    private final HttpStatus status;
    public CustomClientErrorException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }
}
