package com.APIgateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

@RequiredArgsConstructor
@Configuration
public class GatewayConfiguration {

    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("user-service-1", predicateSpec -> predicateSpec
                        .path("/register", "/login")
                        .and().method(HttpMethod.POST)
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .removeRequestHeader(HttpHeaders.COOKIE)
                        )
                        .uri("lb://USERS")
                )
                .route("product-service", predicateSpec -> predicateSpec
                        .path("/api/product/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .removeRequestHeader(HttpHeaders.COOKIE)
                                .filter(jwtAuthorizationFilter) // 이미 생성된 JwtAuthorizationFilter 필터 사용
                        )
                        .uri("lb://BRAND")
                )
                .route("main-service", predicateSpec -> predicateSpec
                        .path("/api/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .removeRequestHeader(HttpHeaders.COOKIE)
                                .filter(jwtAuthorizationFilter) // 이미 생성된 JwtAuthorizationFilter 필터 사용
                        )
                        .uri("lb://BRAND")
                )
                .route("client-service", predicateSpec -> predicateSpec
                        .path("/client/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(new JwtAuthorizationFilter("client")) // "client" 역할을 위한 필터
                        )
                        .uri("lb://BRAND")
                )
                .route("master-service", predicateSpec -> predicateSpec
                        .path("/master/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(new JwtAuthorizationFilter("master")) // "master" 역할을 위한 필터
                        )
                        .uri("lb://USERS")
                )
                .route("owner-service", predicateSpec -> predicateSpec
                        .path("/owner/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(new JwtAuthorizationFilter("owner")) // "owner" 역할을 위한 필터
                        )
                        .uri("lb://BRAND")
                )
                .build();
    }
}
