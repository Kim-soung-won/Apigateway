package com.web.apigateway.config;

import com.web.apigateway.filter.AuthorizationHeaderFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.core.env.Environment;

public class FilterConfig {
    Environment env;

    public FilterConfig(Environment env) {
        this.env = env;
    }

    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder, AuthorizationHeaderFilter filter){
        return builder.routes().build();
    }
}
