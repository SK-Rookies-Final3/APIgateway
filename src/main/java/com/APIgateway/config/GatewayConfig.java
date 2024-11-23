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

                // Users - register
                .route("users-register", predicateSpec -> predicateSpec
                        .path("/open-api/user/register/")
                        .uri("lb://USERS") // 필터 제거
                )

                // Users - login
                .route("users-login", predicateSpec -> predicateSpec
                        .path("/open-api/user/login/")
                        .uri("lb://USERS") // 필터 제거
                )

                // Users - update
                .route("users-update", predicateSpec -> predicateSpec
                        .path("/api/user/update")
                        .uri("lb://USERS") // 필터 제거
                )

                // Users - 조회
                .route("users", predicateSpec -> predicateSpec
                        .path("/api/user")
                        .uri("lb://USERS") // 필터 제거
                )

                // Users - exit
                .route("users-exit", predicateSpec -> predicateSpec
                        .path("/api/user")
                        .uri("lb://USERS") // 필터 제거
                )

                // Users - id 에서 유저 찾기
                .route("users-id", predicateSpec -> predicateSpec
                        .path("/api/user/{id}")
                        .uri("lb://USERS") // 필터 제거
                )


                // Users - master
                .route("users-master", predicateSpec -> predicateSpec
                        .path("/api/user/master")
                        .uri("lb://USERS") // 필터 제거
                )

                // Users - exit/{targetId}
                .route("users-exit-target", predicateSpec -> predicateSpec
                        .path("/api/user/master/exit/{targetId}")
                        .uri("lb://USERS") // 필터 제거
                )


                // Brand - store 등록 요청
                .route("store-owner-register", predicateSpec -> predicateSpec
                        .path("/api/brand/store/owner/register")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )


                // Brand - store 권한 수정
                .route("store-update-status", predicateSpec -> predicateSpec
                        .path("/api/brand/store/master/{storeId}/status")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // Brand - store 전체 조회
                .route("store", predicateSpec -> predicateSpec
                        .path("/open-api/brand/store/")
                        .uri("lb://BRAND") // 필터 제거
                )

                // Brand - store 상세 조회
                .route("store-{storeId}", predicateSpec -> predicateSpec
                        .path("/open-api/brand/store/{storeId}")
                        .uri("lb://BRAND") // 필터 제거
                )

                // 사용자(owner) 본인의 가게 상태(status) 조회
                .route("store-owner-status", predicateSpec -> predicateSpec
                        .path("/api/brand/store/owner/status")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // 사용자(owner) 본인의 가게 상세 조회
                .route("store-owner", predicateSpec -> predicateSpec
                        .path("/api/brand/store/owner")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // brand - product 상품 등록
                .route("product-register-owner", predicateSpec -> predicateSpec
                        .path("/api/brand/product/owner/{storeId}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // brand - product 상품 수정
                .route("product-update-owner", predicateSpec -> predicateSpec
                        .path("/api/brand/product/owner/{storeId}/{productCode}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // brand - product 상품 삭제
                .route("product-delete-owner", predicateSpec -> predicateSpec
                        .path("/api/brand/product/owner/{storeId}/{productCode}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // Brand - product 전체 조회
                .route("product", predicateSpec -> predicateSpec
                        .path("/open-api/brand/product/")
                        .uri("lb://BRAND") // 필터 제거
                )

                // Brand - product 상세 조회
                .route("product-{productCode}", predicateSpec -> predicateSpec
                        .path("/open-api/brand/product/{productCode}")
                        .uri("lb://BRAND") // 필터 제거
                )


                // Brand - review 조회
                .route("review-{productCode}", predicateSpec -> predicateSpec
                        .path("/open-api/brand/product/{productCode}")
                        .uri("lb://BRAND") // 필터 제거
                )

                // Brand - review 등록
                .route("review", predicateSpec -> predicateSpec
                        .path("/api/brand/review/{productCode}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // Brand - review 삭제
                .route("review-{reviewId}", predicateSpec -> predicateSpec
                        .path("/api/brand/review/{reviewId}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://BRAND")
                )

                // order 주문 생성
                .route("order", predicateSpec -> predicateSpec
                        .path("/api/order/{storeId}")
                        .filters(gatewayFilterSpec -> gatewayFilterSpec
                                .filter(jwtAuthorizationFilter)
                        )
                        .uri("lb://ORDER")
                )

                // AI - 유튜브 숏츠 긍/부정
                .route("shorts-search", predicateSpec -> predicateSpec
                        .path("/api/shorts/search")
                        .uri("lb://AI-Sentiment_Classification") // 필터 제거
                )

                // Swagger UI 라우팅
                .route("swagger-ui", predicateSpec -> predicateSpec
                        .path("/swagger-ui/**", "/v3/api-docs/**")
                        .uri("http://localhost:8081")  // Swagger UI가 실행 중인 서비스의 URL로 변경
                )
                .build();
    }
}