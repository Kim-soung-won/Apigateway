package com.web.apigateway.constants;

import java.util.List;

public class Constants {

    public static final String AUTH_VALIDATE_URL = "/api/auth/validate";


    public static final String ACCESS_TOKEN_HEADER = "Authorization";
    public static final String REFRESH_TOKEN_HEADER = "refreshtoken";

    public static final String X_AUTHENTICATED_USERNAME_HEADER = "X-Authenticated-Username";

    public static final List<String> BYPASS_PATHS = List.of("/api/no-auth", "/swagger-ui" ,"/swagger-resources", "/health-check", "/metadata");

    private Constants() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }
}
