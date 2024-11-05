package com.APIgateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.core.io.buffer.DataBuffer;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import javax.annotation.PostConstruct;

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtAuthorizationFilter implements GatewayFilter {

    @Value("${auth.jwt.key}")
    private String key;  // JWT 서명에 사용할 키

    private final ObjectMapper objectMapper;  // JSON 직렬화/역직렬화 도구

    private static final int ERROR_NO_AUTH = 701;  // 인증 헤더가 없을 경우의 에러 코드
    private static final int ERROR_TOKEN_EXPIRED = 702;  // 만료된 토큰에 대한 에러 코드
    private static final int ERROR_UNKNOWN = 999;  // 기타 오류에 대한 에러 코드

    private SecretKey secretKey;  // JWT 서명 검증에 사용할 SecretKey

    @Value("${auth.jwt.requiredRole:}")
    private String requiredRole;  // 필수 역할 (빈 값이면 모든 역할 허용)

    // @PostConstruct는 빈 초기화 메서드로, 필터가 생성된 후 비밀 키를 초기화합니다.
    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));  // JWT 서명 검증 키 초기화
    }

    // 필터 메서드: 클라이언트 요청을 처리하고 JWT 토큰 인증을 검증합니다.
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        try {
            List<String> authorizations = getAuthorizations(exchange);  // Authorization 헤더 추출

            // 인증 헤더가 없다면 에러 응답 반환
            if (isAuthorizationHeaderMissing(authorizations)) {
                return sendErrorResponse(exchange, ERROR_NO_AUTH, new NotExistsAuthorization());
            }

            String jwtToken = parseAuthorizationToken(authorizations.get(0));  // Bearer 토큰 추출

            // JWT 유효성 검사 및 역할 검증
            Claims claims = parseAndValidateJwt(jwtToken);

            // JWT에서 사용자 역할을 추출하고 유효성 검사
            String userRole = claims.get("roles", String.class);
            if (!isRoleValid(userRole)) {
                return sendErrorResponse(exchange, HttpStatus.FORBIDDEN.value(),
                        new UnauthorizedAccessException("User does not have the required role"));
            }

            // JWT의 subject를 요청 헤더에 추가 (인증된 사용자 정보)
            exchange.getRequest().mutate().header("X-Gateway-Header", claims.getSubject());
            return chain.filter(exchange);  // 다음 필터로 요청을 전달
        } catch (Exception e) {
            // 예외가 발생하면 에러 응답 반환
            return sendErrorResponse(exchange, getErrorCode(e), e);
        }
    }

    // JWT 토큰을 파싱하고 유효성을 검증하는 메서드
    private Claims parseAndValidateJwt(String jwtToken) {
        Claims claims = parseJwt(jwtToken);  // JWT 파싱
        validateJwtToken(claims);  // 유효성 검사
        return claims;
    }

    // JWT 토큰을 파싱하여 Claims 객체로 반환
    private Claims parseJwt(String jwtToken) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)  // 서명 검증 키 설정
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();  // JWT의 body를 반환 (Claims 객체)
    }

    // JWT의 만료 시간 확인 및 만료된 토큰에 대해 예외 발생
    private void validateJwtToken(Claims claims) {
        Date expiration = claims.getExpiration();
        if (expiration.before(new Date())) {
            throw new AccessTokenExpiredException();  // 토큰 만료 예외 발생
        }
    }

    // 사용자 역할이 유효한지 확인하는 메서드
    private boolean isRoleValid(String userRole) {
        if (requiredRole == null || requiredRole.isEmpty()) {
            throw new UnauthorizedAccessException("Role is required but not specified.");
        }
        List<String> validRoles = List.of(requiredRole.split(","));
        return validRoles.contains(userRole);  // 사용자 역할이 유효한지 체크
    }


    // 예외 타입에 따라 적절한 에러 코드 반환
    private int getErrorCode(Exception e) {
        if (e instanceof NotExistsAuthorization) return ERROR_NO_AUTH;
        if (e instanceof AccessTokenExpiredException) return ERROR_TOKEN_EXPIRED;
        return ERROR_UNKNOWN;  // 그 외의 예외에 대해서는 UNKNOWN 에러 코드 반환
    }

    // 에러 응답을 반환하는 메서드
    private Mono<Void> sendErrorResponse(ServerWebExchange exchange, int errorCode, Exception e) {
        try {
            log.error("Error occurred with token: {} - {} - {}", e.getClass().getSimpleName(), errorCode, e.getMessage());

            // 에러 응답을 JSON 형식으로 생성
            ErrorResponse errorResponse = new ErrorResponse(errorCode, e.getMessage());
            String errorBody = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(errorResponse);

            // 응답 상태 코드 및 헤더 설정
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.valueOf(errorCode));
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            // 에러 메시지를 바이트 버퍼로 변환하여 응답
            DataBuffer buffer = response.bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8));
            return response.writeWith(Flux.just(buffer));
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Failed to process error response", ex);
        }
    }

    // Authorization 헤더에서 토큰 추출
    private List<String> getAuthorizations(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        return request.getHeaders().getOrDefault(HttpHeaders.AUTHORIZATION, List.of());
    }

    // Authorization 헤더에서 "Bearer "로 시작하는 토큰을 파싱
    private String parseAuthorizationToken(String authorization) {
        if (authorization.startsWith("Bearer ")) {
            return authorization.substring(7).trim();  // "Bearer " 이후의 토큰 추출
        }
        throw new IllegalArgumentException("Invalid Authorization header format");
    }

    // Authorization 헤더가 없는지 확인
    private boolean isAuthorizationHeaderMissing(List<String> authorizations) {
        return authorizations.isEmpty();
    }

    // 인증 헤더가 없을 경우 발생하는 예외 클래스
    public static class NotExistsAuthorization extends RuntimeException {
        public NotExistsAuthorization() {
            super("Authorization header is missing.");
        }
    }

    // 만료된 JWT 토큰에 대해 발생하는 예외 클래스
    public static class AccessTokenExpiredException extends RuntimeException {
        public AccessTokenExpiredException() {
            super("Access token is expired.");
        }
    }

    // 권한이 없을 경우 발생하는 예외 클래스
    public static class UnauthorizedAccessException extends RuntimeException {
        public UnauthorizedAccessException(String message) {
            super(message);
        }
    }

    // 오류 응답 객체 클래스
    record ErrorResponse(int code, String message) {}
}
