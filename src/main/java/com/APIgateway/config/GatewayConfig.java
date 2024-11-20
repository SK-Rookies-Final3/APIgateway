package com.APIgateway.config;

import com.APIgateway.filter.JwtAuthorizationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
public class GatewayConfig {

    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()

                // Brand - store 등록 요청
                .route("store-owner-register", predicateSpec -> predicateSpec
                        .path("/api/store/owner/register")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // Brand - store 권한 수정
                .route("store-update-status", predicateSpec -> predicateSpec
                        .path("/api/store/master/{storeId}/status")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // Brand - store 전체 조회
                .route("store", predicateSpec -> predicateSpec
                        .path("/open-api/store/")
                        .uri("lb://BRAND") // 필터 제거
                )

                // Brand - store 상세 조회
                .route("store-{storeId}", predicateSpec -> predicateSpec
                        .path("/open-api/store/{storeId}")
                        .uri("lb://BRAND") // 필터 제거
                )

                // 사용자(owner) 본인의 가게 상태(status) 조회 라우트 추가
                .route("store-owner-status", predicateSpec -> predicateSpec
                        .path("/api/store/owner/status/{userId}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // brand - product 상품 등록
                .route("product-register-owner", predicateSpec -> predicateSpec
                        .path("/api/product/owner/{storeId}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // brand - product 상품 수정
                .route("product-update-owner", predicateSpec -> predicateSpec
                        .path("/api/product/owner/{storeId}/{productCode}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // brand - product 상품 삭제
                .route("product-delete-owner", predicateSpec -> predicateSpec
                        .path("/api/product/owner/{storeId}/{productCode}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // Brand - product 전체 조회
                .route("product", predicateSpec -> predicateSpec
                        .path("/open-api/product/")
                        .uri("lb://BRAND") // 필터 제거
                )

                // Brand - product 상세 조회
                .route("product-{productCode}", predicateSpec -> predicateSpec
                        .path("/open-api/product/{productCode}")
                        .uri("lb://BRAND") // 필터 제거
                )


                // Swagger UI 라우팅
                .route("swagger-ui", predicateSpec -> predicateSpec
                        .path("/swagger-ui/**", "/v3/api-docs/**")
                        .uri("http://localhost:8081")  // Swagger UI가 실행 중인 서비스의 URL로 변경
                )
                .build();
    }

}
