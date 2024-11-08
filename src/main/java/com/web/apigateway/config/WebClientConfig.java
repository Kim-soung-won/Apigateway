package com.web.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient authServiceWebClient(Environment env) {
        String authServiceUrl = env.getProperty("auth-service-url");
        return WebClient.builder()
                .baseUrl(authServiceUrl) // 설정된 URL 사용
                .build();
    }
}
