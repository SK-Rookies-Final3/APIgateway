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
                                .path("/open-api/user/register")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )

                        // Users - login
                        .route("users-login", predicateSpec -> predicateSpec
                                .path("/open-api/user/login")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )

                        // Users - update
                        .route("users-update", predicateSpec -> predicateSpec
                                .path("/api/user/update")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )

                        // Users - 조회
                        .route("users", predicateSpec -> predicateSpec
                                .path("/api/user")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )

                        // Users - exit
                        .route("users-exit", predicateSpec -> predicateSpec
                                .path("/api/user/exit/{id}")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )

                        // Users - id 에서 유저 찾기
                        .route("users-id", predicateSpec -> predicateSpec
                                .path("/api/user/{id}")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )


                        // Users - master
                        .route("users-master", predicateSpec -> predicateSpec
                                .path("/api/user/master")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )

                        // Users - exit/{targetId}
                        .route("users-exit-target", predicateSpec -> predicateSpec
                                .path("/api/user/master/exit/{targetId}")
                                .uri("lb://shortpingoo-backend-users-svc")
                        )


                        // Brand - store 등록 요청
                        .route("store-owner-register", predicateSpec -> predicateSpec
                                .path("/api/brand/store/owner/register")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )


                        // Brand - store 권한 수정
                        .route("store-update-status", predicateSpec -> predicateSpec
                                .path("/api/brand/store/master/{storeId}/status")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - store 전체 조회
                        .route("store", predicateSpec -> predicateSpec
                                .path("/open-api/brand/store")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - store 상세 조회
                        .route("store-{storeId}", predicateSpec -> predicateSpec
                                .path("/open-api/brand/store/{storeId}")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )


                        // 사용자(owner) 본인의 가게 상태(status) 조회
                        .route("store-owner-status", predicateSpec -> predicateSpec
                                .path("/api/brand/store/owner/status/{userId}")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // 사용자(owner) 본인의 가게 상세 조회
                        .route("store-owner", predicateSpec -> predicateSpec
                                .path("/api/brand/store/owner")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // brand - product 상품 등록
                        .route("product-register-owner", predicateSpec -> predicateSpec
                                .path("/api/brand/product/owner/{storeId}")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // brand - product 상품 수정
                        .route("product-update-owner", predicateSpec -> predicateSpec
                                .path("/api/brand/product/owner/{storeId}/{productCode}")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // brand - product 상품 삭제
                        .route("product-delete-owner", predicateSpec -> predicateSpec
                                .path("/api/brand/product/owner/{storeId}/{productCode}")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - product 전체 조회
                        .route("product", predicateSpec -> predicateSpec
                                .path("/open-api/brand/product")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - product 상세 조회
                        .route("product-{productCode}", predicateSpec -> predicateSpec
                                .path("/open-api/brand/product/{productCode}")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - product 상세 조회
                        .route("product-{category}", predicateSpec -> predicateSpec
                                .path("/open-api/brand/product/category/{category}")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - product 가게별 상품 전체 조회
                        .route("product-{storeId}", predicateSpec -> predicateSpec
                                .path("/open-api/brand/product/store/{storeId}")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // 사용자(owner) 본인의 가게의 상품 상세 조회
                        .route("product-owner", predicateSpec -> predicateSpec
                                .path("/api/brand/product/owner")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // 사용자(owner) 본인의 가게의 상품 상세 조회
                        .route("product-owner", predicateSpec -> predicateSpec
                                .path("/api/brand/product/ownerRest")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )


                        // Brand - review 조회
                        .route("review-{productCode}", predicateSpec -> predicateSpec
                                .path("/open-api/brand/product/{productCode}")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - review 등록
                        .route("review", predicateSpec -> predicateSpec
                                .path("/api/brand/review/{productCode}")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // Brand - review 삭제
                        .route("review-{reviewCode}", predicateSpec -> predicateSpec
                                .path("/api/brand/review/{reviewCode}")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // order 주문 생성
                        .route("order", predicateSpec -> predicateSpec
                                .path("/api/order")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-order-svc")
                        )

                        // order - 사용자(client)별 전체 주문 내역 조회
                        // code 는 order 테이블의 index code 이다.
                        .route("order-client", predicateSpec -> predicateSpec
                                .path("/api/order/client")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-order-svc")
                        )

                        // order - 사용자(owner)별 가게의 전체 주문 내역 조회
                        .route("order-owner", predicateSpec -> predicateSpec
                                .path("/api/order/owner")
                                .filters(gatewayFilterSpec -> gatewayFilterSpec
                                        .filter(jwtAuthorizationFilter)
                                )
                                .uri("lb://shortpingoo-backend-order-svc")
                        )

                        // 상품 별 재고 수정
                        .route("product-stock", predicateSpec -> predicateSpec
                                .path("/open-api/brand/product/stock/{productCode}")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        // 상품 별 재고 조회
                        .route("product-stock", predicateSpec -> predicateSpec
                                .path("/open-api/brand/product/stock/{productCode}")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )



                        // AI - 유튜브 숏츠 긍/부정
                        .route("shorts-search", predicateSpec -> predicateSpec
                                .path("/api/shorts/search")
                                .uri("lb://shortpingoo-ai-flask-svc")
                        )

                        // 로컬 이미지 파일 접근
                        .route("image-access", predicateSpec -> predicateSpec
                                .path("/uploads/**")
                                .uri("lb://shortpingoo-backend-brand-svc")
                        )

                        
                        // 장바구니 관련 라우트, JWT 인증 필터 적용

                       .route("cart-items", predicateSpec -> predicateSpec
                               .path("/api/cart/items")
                               .filters(gatewayFilterSpec -> gatewayFilterSpec
                                       .filter(jwtAuthorizationFilter)
                               )
                               .uri("lb://shortpingoo-backend-cart-svc")
                       )

                       .route("cart-item-by-productCode", predicateSpec -> predicateSpec
                               .path("/api/cart/items/{productCode}")
                               .filters(gatewayFilterSpec -> gatewayFilterSpec
                                       .filter(jwtAuthorizationFilter)
                               )
                               .uri("lb://shortpingoo-backend-cart-svc")
                       )

                       .route("custom-cart-items", predicateSpec -> predicateSpec
                               .path("/api/cart/custom/items")
                               .filters(gatewayFilterSpec -> gatewayFilterSpec
                                       .filter(jwtAuthorizationFilter)
                               )
                               .uri("lb://shortpingoo-backend-cart-svc")
                       )

                       .route("update-cart-title", predicateSpec -> predicateSpec
                               .path("/api/cart/custom/updateTitle")
                               .filters(gatewayFilterSpec -> gatewayFilterSpec
                                       .filter(jwtAuthorizationFilter)
                               )
                               .uri("lb://shortpingoo-backend-cart-svc")
                       )

                       .route("custom-cart-item-by-productCode", predicateSpec -> predicateSpec
                               .path("/api/cart/custom/items/{productCode}")
                               .filters(gatewayFilterSpec -> gatewayFilterSpec
                                       .filter(jwtAuthorizationFilter)
                               )
                               .uri("lb://shortpingoo-backend-cart-svc")
                       )
//
//                        // 위시리스트 관련 라우트, JWT 인증 필터 적용
//                        .route("wish-product", predicateSpec -> predicateSpec
//                                .path("/api/wishlist/products")
//                                .filters(gatewayFilterSpec -> gatewayFilterSpec
//                                        .filter(jwtAuthorizationFilter)
//                                )
//                                .uri("lb://WISHLISHT")
//                        )
//                        .route("wish-shorts", predicateSpec -> predicateSpec
//                                .path("/api/wishlist/shorts")
//                                .filters(gatewayFilterSpec -> gatewayFilterSpec
//                                        .filter(jwtAuthorizationFilter)
//                                )
//                                .uri("lb://WISHLISHT")
//                        )
//                        .route("wish-product-Delete", predicateSpec -> predicateSpec
//                                .path("/api/wishlist/products/{productCode}")
//                                .filters(gatewayFilterSpec -> gatewayFilterSpec
//                                        .filter(jwtAuthorizationFilter)
//                                )
//                                .uri("lb://WISHLISHT")
//                        )
//                        .route("wish-shorts-Delete", predicateSpec -> predicateSpec
//                                .path("/api/wishlist/shorts/{shortsCode}")
//                                .filters(gatewayFilterSpec -> gatewayFilterSpec
//                                        .filter(jwtAuthorizationFilter)
//                                )
//                                .uri("lb://WISHLISHT")
//                        )


                        // Swagger UI 라우팅
                        .route("swagger-ui", predicateSpec -> predicateSpec
                                .path("/swagger-ui/**", "/v3/api-docs/**")
                                .uri("http://localhost:8081")  // Swagger UI가 실행 중인 서비스의 URL로 변경
                        )
                        .build();
        }
}
