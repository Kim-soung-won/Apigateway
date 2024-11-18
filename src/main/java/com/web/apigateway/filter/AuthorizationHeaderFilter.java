package com.web.apigateway.filter;

import com.web.apigateway.constants.Constants;
import com.web.apigateway.exception.CustomClientErrorException;
import com.web.apigateway.exception.RecordException;
import com.web.apigateway.service.CircuitBreakerService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.util.List;
import java.util.Objects;

@Component
@Slf4j
// Request Header에 관한 것을 Filter로 처리
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final WebClient authClient;
    private final CircuitBreakerService circuitBreakerService;
    Environment env;

    public AuthorizationHeaderFilter(WebClient authClient,
                                     CircuitBreakerService circuitBreakerService,
                                     Environment env) {
        super(Config.class);
        this.authClient = authClient;
        this.circuitBreakerService = circuitBreakerService;
        this.env = env;
    }

    @Data
    public static class Config {
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            log.info("Authorization Filter baseMessage: {}, {}", config.getBaseMessage(), request.getRemoteAddress());

            String requestPath = request.getURI().getPath(); // 요청 경로를 가져옴
            if (Constants.BYPASS_PATHS.stream().anyMatch(requestPath::contains)) {
                // 요청 경로가 BYPASS_PATHS에 포함되어 있는지 확인
                return chain.filter(exchange); // 포함되어 있으면 다음 필터로 이동
            }

            //Authorization 헤더 가져오기 (Access Token을 의미한다.)
            String authHeader = request.getHeaders().getFirst(Constants.ACCESS_TOKEN_HEADER);
            if(authHeader == null) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // 인증 및 토큰 유효성 체크
            return authenticateAndFilter(exchange, chain, authHeader);
        };
    }

    //ServerWebExchange : Spring WebFlux에서 Http 요청 - 응답 상호작용을 수행하여 요청, 응답, 속성 등에 대한 접근을 제공한다.
    //GatewayFilterChain : GatewayFilter의 체인을 나타내며, GatewayFilter를 순차적으로 실행하고, 다음 필터를 호출하는 역할을 한다.
    //Mono : 단일 결과를 반환하는 비동기 작업에 시행된다. 최대 1개의 항목만을 다룬다.
    public Mono<Void> authenticateAndFilter(ServerWebExchange exchange, GatewayFilterChain chain, String authHeader){
        log.info("authHeader : {}", authHeader);
        return authClient
                .method(HttpMethod.GET)
                .uri(uriBuilder -> uriBuilder.path(Constants.AUTH_VALIDATE_URL).build())
                .headers(httpHeaders -> {
                    HttpHeaders originalHeaders = exchange.getRequest().getHeaders();
                    log.info("originalHeaders : {}", originalHeaders);

                    httpHeaders.setContentType(MediaType.APPLICATION_JSON);
                    httpHeaders.set(HttpHeaders.AUTHORIZATION, authHeader);
                    log.info("Final Headers: {}", httpHeaders);
                })
                .accept(MediaType.APPLICATION_JSON)
                .retrieve() // 위에 세팅한 Http 요청을 전송한다.
                .onStatus(HttpStatusCode::is4xxClientError, // 요청의 결과가 4xx 에러 코드라면
                        clientResponse -> clientResponse.bodyToMono(String.class)
                                .flatMap(body -> {
                                    log.error("Client error: status = {}, body = {}", clientResponse.statusCode(), body);
                                    HttpStatus status = (HttpStatus) clientResponse.statusCode();
                                    return Mono.error(new CustomClientErrorException(status, "Authentication failed: " + body));
                                })
                )
                .onStatus(HttpStatusCode::is5xxServerError, // 요청의 결과가 5xx 에러 코드라면
                        clientResponse -> clientResponse.bodyToMono(String.class)
                                .flatMap(body -> {
                                    log.error("Server error: status = {}, body = {}", clientResponse.statusCode(), body);
                                    return Mono.error(new RuntimeException("Server Error: " + clientResponse.statusCode() + "-" + body));
                                })
                )
                .toBodilessEntity()
                .onErrorResume(ConnectException.class, e -> {
                    String errorMessage = circuitBreakerService.authClientError("인증 서버 연결 실패로 인한 인증 실패");
                    return Mono.error(new ConnectException("Server Error: " + errorMessage));
                })
                .onErrorResume(WebClientRequestException.class, e ->{
                    String errorMessage = circuitBreakerService.authClientError("인증 서버 연결 실패로 인한 인증 실패");
                    return Mono.error(new ConnectException("Server Error: " + errorMessage));
                })
                .flatMap(responseEntity -> handleResponse(exchange, chain, responseEntity))
                .onErrorResume(e -> handleError(exchange, e));
    }

    // 응답 가공
    private Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, ResponseEntity<Void> responseEntity){
        // Auth로부터 온 응답에서 Username 헤더를 추출한다.
        List<String> usernameHeaders = responseEntity.getHeaders().get(Constants.X_AUTHENTICATED_USERNAME_HEADER);

        // 헤더가 없다면, 인증에 성공하지 못한 것 이기 때문에, 401 에러를 반환한다.
        if (usernameHeaders == null || usernameHeaders.isEmpty()) {
            return Mono.error(new CustomClientErrorException(HttpStatus.UNAUTHORIZED, "Missing authentication headers"));
        }
        String username = usernameHeaders.get(0);

        ServerHttpRequest mutatedRequest = mutateRequestWithHeaders(exchange, username);

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private ServerHttpRequest mutateRequestWithHeaders(ServerWebExchange exchange, String username){
        HttpHeaders headers = new HttpHeaders();

        headers.add(Constants.X_AUTHENTICATED_USERNAME_HEADER, username);

        return exchange.getRequest().mutate()
                .headers(httpHeaders -> httpHeaders.addAll(headers))
                .build();
    }

    private Mono<Void> handleError(ServerWebExchange exchange, Throwable e) {
        if (e instanceof CustomClientErrorException) {
            HttpStatus status = ((CustomClientErrorException) e).getStatus();
            log.error("Error status: {}", status);
            exchange.getResponse().setStatusCode(status);
        } else if(e instanceof ConnectException){
            exchange.getResponse().setStatusCode(HttpStatus.REQUEST_TIMEOUT);
        } else {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        }
        return exchange.getResponse().setComplete();
    }
}
