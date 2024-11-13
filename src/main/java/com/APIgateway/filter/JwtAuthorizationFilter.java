package com.APIgateway.filter;

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

    // JWT 서명키, users 서비스의 키와 똑같이 맞춰야 함
    @Value("${JWT_SECRET}")
    private String key;

    private final ObjectMapper objectMapper;

    private static final int ERROR_NO_AUTH = 701;  // 인증 헤더가 없을 경우의 에러 코드
    private static final int ERROR_TOKEN_EXPIRED = 702;  // 만료된 토큰에 대한 에러 코드
    private static final int ERROR_UNKNOWN = 999;  // 기타 오류에 대한 에러 코드

    private SecretKey secretKey;

    // JWT 서명 검증 키 초기화: 바이트 변환 안하면 토큰을 검증하는게 아니라 문자열로 검증하게 됨
    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
    }

    // 메인 필터
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        try {
            List<String> authorizations = getAuthorizations(exchange);  // Authorization 헤더 추출

            if (isAuthorizationHeaderMissing(authorizations)) {
                return sendErrorResponse(exchange, ERROR_NO_AUTH, new NotExistsAuthorization());
            }

            String jwtToken = authorizations.get(0);  // 토큰 반환
            Claims claims = parseAndValidateJwt(jwtToken); // 토큰 파싱 및 검증

            // 토큰에서 userId 추출
            Integer userId = claims.get("id", Integer.class);

            if (userId == null) {
                return sendErrorResponse(exchange, ERROR_UNKNOWN, new UnauthorizedAccessException("User ID is missing in token"));
            }


            // 사용자 ID를 요청 헤더에 추가
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", String.valueOf(userId))
                    .build();

            // 수정된 요청을 새로운 ServerWebExchange로 설정
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        } catch (Exception e) {
            return sendErrorResponse(exchange, getErrorCode(e), e);
        }
    }

    // 토큰 파싱 및 검증
    private Claims parseAndValidateJwt(String jwtToken) {
        Claims claims = parseJwt(jwtToken);
        validateJwtToken(claims);
        return claims;
    }

    // 토큰 파싱
    private Claims parseJwt(String jwtToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(jwtToken) // 서명 검증 및 디코딩
                    .getBody();  // 바디(페이로드) 반환
        } catch (Exception e) {
            log.error("JWT parsing error", e);  // 예외 발생 시 로그
            throw new UnauthorizedAccessException("Invalid token");
        }
    }

    // 시간 만료에 따른 토큰 검증
    private void validateJwtToken(Claims claims) {
        Date expiration = claims.getExpiration();
        if (expiration.before(new Date())) {
            throw new AccessTokenExpiredException();
        }
    }

    private int getErrorCode(Exception e) {
        log.debug("error:://"+e.toString());
        if (e instanceof NotExistsAuthorization) return ERROR_NO_AUTH;
        if (e instanceof AccessTokenExpiredException) return ERROR_TOKEN_EXPIRED;

        return ERROR_UNKNOWN;
    }

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

    // Authorization 헤더 가져오기
    private List<String> getAuthorizations(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        return request.getHeaders().getOrDefault(HttpHeaders.AUTHORIZATION, List.of());
    }

    private String parseAuthorizationToken(String authorization) {
        // Bearer 없이 토큰을 바로 반환하도록 수정
        return authorization.trim();
    }

    private boolean isAuthorizationHeaderMissing(List<String> authorizations) {
        return authorizations.isEmpty();
    }

    public static class NotExistsAuthorization extends RuntimeException {
        public NotExistsAuthorization() {
            super("Authorization header is missing.");
        }
    }

    public static class AccessTokenExpiredException extends RuntimeException {
        public AccessTokenExpiredException() {
            super("Access token is expired.");
        }
    }

    public static class UnauthorizedAccessException extends RuntimeException {
        public UnauthorizedAccessException(String message) {
            super(message);
        }
    }

    record ErrorResponse(int code, String message) {}
}
