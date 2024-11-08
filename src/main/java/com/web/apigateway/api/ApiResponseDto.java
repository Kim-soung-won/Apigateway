package com.web.apigateway.api;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.Serializable;

@Data
@Slf4j
public class ApiResponseDto<T> implements Serializable {

    private boolean success;
    private T data;
    private String message;


    public ApiResponseDto(){}

    public ApiResponseDto(boolean success){
        this.success = success;
    }

    public ApiResponseDto(boolean success, T data){
        this.success = success;
        this.data = data;
    }

    public ApiResponseDto(boolean success, T data, String message){
        this.success = success;
        this.data = data;
        this.message = message;
    }

}
