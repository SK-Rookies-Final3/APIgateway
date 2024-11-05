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
                .route("user-service-2", predicateSpec -> predicateSpec
                        .path("/master/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .removeRequestHeader(HttpHeaders.COOKIE)
                                .filter(jwtAuthorizationFilter)
                                .addRequestHeader("X-Required-Role", "master")
                        )
                        .uri("lb://USERS")
                )
                .route("user-service-2", predicateSpec -> predicateSpec
                        .path("/api/wishlist/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .removeRequestHeader(HttpHeaders.COOKIE)
                                .filter(jwtAuthorizationFilter)
                                .addRequestHeader("X-Required-Role", "client")
                        )
                        .uri("lb://WISHLIST")
                )
                .route("user-service-2", predicateSpec -> predicateSpec
                        .path("/user/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .removeRequestHeader(HttpHeaders.COOKIE)
                                .filter(jwtAuthorizationFilter)
                                .addRequestHeader("X-Required-Role", "client")
                        )
                        .uri("lb://USERS")
                )
                .route("main-service", predicateSpec -> predicateSpec
                        .path("/owner/**")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .removeRequestHeader(HttpHeaders.COOKIE)
                                .filter(jwtAuthorizationFilter)
                                .addRequestHeader("X-Required-Role", "owner")
                        )
                        .uri("lb://BRAND")
                )
                .build();
    }
}
