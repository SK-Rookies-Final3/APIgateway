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

                .route("store-owner-register", predicateSpec -> predicateSpec
                        .path("/api/store/owner/register")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)  // JwtAuthorizationFilter에서 토큰을 추출하여 헤더에 추가
                        )
                        .uri("lb://BRAND") // 서비스 이름으로 포워딩 (Eureka 서비스 레지스트리)
                )

                .route("store-some-endpoint", predicateSpec -> predicateSpec
                        .path("/api/store/some-endpoint")  // 요청 경로
                        .uri("lb://BRAND")  // 서비스 이름으로 포워딩 (Eureka 서비스 레지스트리)
                )

                // Swagger UI 라우팅
                .route("swagger-ui", predicateSpec -> predicateSpec
                        .path("/swagger-ui/**", "/v3/api-docs/**")
                        .uri("http://192.168.0.71:8081")  // Swagger UI가 실행 중인 서비스의 URL로 변경
                )
                .build();

    }
}
