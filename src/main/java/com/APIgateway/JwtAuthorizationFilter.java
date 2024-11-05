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
    private String key;

    private final ObjectMapper objectMapper;

    private static final int ERROR_NO_AUTH = 701;
    private static final int ERROR_TOKEN_EXPIRED = 702;
    private static final int ERROR_UNKNOWN = 999;

    // SecretKey는 불변 객체이므로 초기화
    private SecretKey secretKey;

    @Value("${auth.jwt.requiredRole:}")
    private String requiredRole;  // 필수 역할

    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        try {
            List<String> authorizations = getAuthorizations(exchange);

            // 인증 헤더가 없으면 에러 반환
            if (isAuthorizationHeaderMissing(authorizations)) {
                return sendErrorResponse(exchange, ERROR_NO_AUTH, new NotExistsAuthorization());
            }

            String jwtToken = parseAuthorizationToken(authorizations.get(0));

            // JWT 유효성 및 역할 검증
            Claims claims = parseAndValidateJwt(jwtToken);

            // 사용자 역할 검사
            String userRole = claims.get("roles", String.class);  // JWT에서 역할 추출
            if (!isRoleValid(userRole)) {
                return sendErrorResponse(exchange, HttpStatus.FORBIDDEN.value(),
                        new UnauthorizedAccessException("User does not have the required role"));
            }

            // JWT에서 subject 추출하여 헤더에 추가
            exchange.getRequest().mutate().header("X-Gateway-Header", claims.getSubject());
            return chain.filter(exchange);
        } catch (Exception e) {
            // 에러 처리
            return sendErrorResponse(exchange, getErrorCode(e), e);
        }
    }

    // JWT 파싱 및 유효성 검사
    private Claims parseAndValidateJwt(String jwtToken) {
        Claims claims = parseJwt(jwtToken);
        validateJwtToken(claims);
        return claims;
    }

    private Claims parseJwt(String jwtToken) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    private void validateJwtToken(Claims claims) {
        Date expiration = claims.getExpiration();
        if (expiration.before(new Date())) {
            throw new AccessTokenExpiredException();
        }
    }

    // 역할 유효성 검사
    private boolean isRoleValid(String userRole) {
        if (requiredRole == null || requiredRole.isEmpty()) {
            throw new UnauthorizedAccessException("Role is required but not specified.");
        }
        return requiredRole.equalsIgnoreCase(userRole);
    }

    // 에러 코드 선택
    private int getErrorCode(Exception e) {
        if (e instanceof NotExistsAuthorization) return ERROR_NO_AUTH;
        if (e instanceof AccessTokenExpiredException) return ERROR_TOKEN_EXPIRED;
        return ERROR_UNKNOWN;
    }

    // 에러 응답 반환
    private Mono<Void> sendErrorResponse(ServerWebExchange exchange, int errorCode, Exception e) {
        try {
            log.error("Error occurred with token: {} - {} - {}", e.getClass().getSimpleName(), errorCode, e.getMessage());

            ErrorResponse errorResponse = new ErrorResponse(errorCode, e.getMessage());
            String errorBody = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(errorResponse);

            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.valueOf(errorCode));
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            DataBuffer buffer = response.bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8));

            return response.writeWith(Flux.just(buffer));
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Failed to process error response", ex);
        }
    }

    private List<String> getAuthorizations(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        return request.getHeaders().getOrDefault(HttpHeaders.AUTHORIZATION, List.of());
    }

    private String parseAuthorizationToken(String authorization) {
        if (authorization.startsWith("Bearer ")) {
            return authorization.substring(7).trim();
        }
        throw new IllegalArgumentException("Invalid Authorization header format");
    }

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

    // 오류 응답 객체
    record ErrorResponse(int code, String message) {}
}