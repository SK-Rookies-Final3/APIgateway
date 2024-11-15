package com.APIgateway.config;

import com.APIgateway.filter.JwtAuthorizationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
public class GatewayConfig {

    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()

                // Brand - store
                .route("store-owner-register", predicateSpec -> predicateSpec
                        .path("/api/store/owner/register")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                .route("store-update-status", predicateSpec -> predicateSpec
                        .path("/api/store/master/{storeId}/status")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )


                // Brand - product
                .route("product-register-owner", predicateSpec -> predicateSpec
                        .path("/api/product/owner/{storeId}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                .route("product-update-owner", predicateSpec -> predicateSpec
                        .path("/api/product/owner/{storeId}/{productCode}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                .route("product-delete-owner", predicateSpec -> predicateSpec
                        .path("api/product/owner/{storeId}/{productCode}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // Swagger UI 라우팅
                .route("swagger-ui", predicateSpec -> predicateSpec
                        .path("/swagger-ui/**", "/v3/api-docs/**")
                        .uri("http://localhost:8081")  // Swagger UI가 실행 중인 서비스의 URL로 변경
                )
                .build();
    }

}
