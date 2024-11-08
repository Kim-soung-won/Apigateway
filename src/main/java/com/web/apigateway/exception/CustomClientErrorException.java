package com.web.apigateway.exception;

import org.springframework.http.HttpStatus;

public class CustomClientErrorException extends RuntimeException {
    private final HttpStatus status;
    public CustomClientErrorException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
