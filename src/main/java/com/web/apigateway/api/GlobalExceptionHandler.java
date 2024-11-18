package com.web.apigateway.api;

import com.web.apigateway.constants.Constants;
import com.web.apigateway.exception.RecordException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.server.ServerWebExchange;

import java.net.ConnectException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ConnectException.class)
    @ResponseStatus(HttpStatus.REQUEST_TIMEOUT)
    public ResponseEntity<?> handleRuntimeException(ServerWebExchange exchange, ConnectException ex) {
        ServerHttpRequest request = exchange.getRequest();
        String serviceName = Constants.extractFirstPart(request.getURI().getPath());
        Map<String, Object> body = new HashMap<>();
        body.put("status", HttpStatus.REQUEST_TIMEOUT.value());
        body.put("error", "Bad Request");
        body.put("message", "Connection Error From Service " + serviceName);

        ApiResponseDto<Map<String, Object>> response = new ApiResponseDto<>(false, body, Constants.CONNECT_ERROR_MESSAGE);
        return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body(response);
    }

    @ExceptionHandler(WebClientRequestException.class)
    @ResponseStatus(HttpStatus.REQUEST_TIMEOUT)
    public ResponseEntity<?> handleRuntimeException(ServerWebExchange exchange, WebClientRequestException ex) {
        ServerHttpRequest request = exchange.getRequest();
        String serviceName = Constants.extractFirstPart(request.getURI().getPath());
        Map<String, Object> body = new HashMap<>();
        body.put("status", HttpStatus.REQUEST_TIMEOUT.value());
        body.put("error", "Bad Request");
        body.put("message", "Connection Error From Service ");

        ApiResponseDto<Map<String, Object>> response = new ApiResponseDto<>(false, body, Constants.CONNECT_ERROR_MESSAGE);
        return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body(response);
    }
}
