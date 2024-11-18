package com.web.apigateway.constants;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Constants {

    public static final String CONNECT_ERROR_MESSAGE = "Could not connect to the service Please ask the administrator to check the service status";

    private static final Pattern PATTERN = Pattern.compile("^/([^/]+)/.*$");

    public static String extractFirstPart(String url) {
        Matcher matcher = PATTERN.matcher(url);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static final String AUTH_VALIDATE_URL = "/api/auth/validate";


    public static final String ACCESS_TOKEN_HEADER = "Authorization";
    public static final String REFRESH_TOKEN_HEADER = "refreshtoken";

    public static final String X_AUTHENTICATED_USERNAME_HEADER = "X-Authenticated-Username";

    public static final List<String> BYPASS_PATHS = List.of("/api/no-auth", "/swagger-ui" ,"/swagger-resources", "/health-check", "/metadata");

    private Constants() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }
}
