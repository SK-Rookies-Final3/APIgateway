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

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtAuthorizationFilter implements GatewayFilter {

    // JWT 비밀 키를 application.properties 파일에서 주입
    @Value("${auth.jwt.key}")
    private String key;

    // ObjectMapper는 오류 응답을 JSON 형식으로 직렬화하기 위해 사용
    private final ObjectMapper objectMapper;

    // 오류 코드 상수들 (인증 오류, 토큰 만료, 기타 예외 처리)
    private static final int ERROR_NO_AUTH = 701;
    private static final int ERROR_TOKEN_EXPIRED = 702;
    private static final int ERROR_UNKNOWN = 999;

    // SecretKey 객체를 클래스 레벨에서 한 번만 생성하여 재사용
    private SecretKey secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));

    // 요청을 필터링하는 메소드. 요청에 JWT가 포함된 인증 헤더가 있는지 확인하고, 유효성을 검사함.
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        try {
            // 요청에서 인증 헤더를 추출
            List<String> authorizations = getAuthorizations(exchange);

            // 인증 헤더가 없으면 인증 오류 응답 반환
            if (isAuthorizationHeaderMissing(authorizations)) {
                return sendErrorResponse(exchange, ERROR_NO_AUTH, new NotExistsAuthorization());
            }

            // JWT 토큰 추출
            String jwtToken = parseAuthorizationToken(authorizations.get(0));

            // JWT 유효성 검사 (만료된 토큰인지 체크)
            validateJwtToken(jwtToken);

            // JWT가 유효하면 요청 헤더에 사용자 정보를 추가하여 다음 필터로 전달
            exchange.getRequest().mutate().header("X-Gateway-Header", getSubjectOf(jwtToken));
            return chain.filter(exchange);
        } catch (NotExistsAuthorization | AccessTokenExpiredException e) {
            // 인증이 없거나 토큰이 만료된 경우 적절한 오류 응답 반환
            return sendErrorResponse(exchange, e instanceof NotExistsAuthorization ? ERROR_NO_AUTH : ERROR_TOKEN_EXPIRED, e);
        } catch (Exception e) {
            // 기타 예기치 않은 오류 처리
            return sendErrorResponse(exchange, ERROR_UNKNOWN, e);
        }
    }

    // JWT 토큰 유효성 검증 (만료 여부 체크)
    private void validateJwtToken(String jwtToken) {
        Claims claims = parseJwt(jwtToken);
        Date expiration = claims.getExpiration();
        if (expiration.before(new Date())) {
            throw new AccessTokenExpiredException(); // 만료된 토큰 예외 발생
        }
    }

    // 오류 발생 시 JSON 형식으로 오류 응답을 반환하는 메소드
    private Mono<Void> sendErrorResponse(ServerWebExchange exchange, int errorCode, Exception e) {
        try {
            // 오류 로그 기록
            log.error("Error occurred: {} - {}", errorCode, e.getMessage());

            // 오류 응답 객체 생성
            ErrorResponse errorResponse = new ErrorResponse(errorCode, e.getMessage());
            String errorBody = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(errorResponse);

            // HTTP 응답 설정 (401 Unauthorized, JSON 형식)
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            DataBuffer buffer = response.bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8));

            // 오류 응답 반환
            return response.writeWith(Flux.just(buffer));
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Failed to process error response", ex);
        }
    }

    // 요청에서 Authorization 헤더를 추출하는 메소드
    private List<String> getAuthorizations(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        return request.getHeaders().getOrDefault(HttpHeaders.AUTHORIZATION, List.of());
    }

    // Authorization 헤더에서 JWT 토큰을 추출하는 메소드
    private String parseAuthorizationToken(String authorization) {
        if (authorization.startsWith("Bearer ")) {
            return authorization.substring(7).trim(); // "Bearer " 이후의 부분을 추출
        }
        throw new IllegalArgumentException("Invalid Authorization header format");
    }

    // Authorization 헤더가 존재하는지 확인하는 메소드
    private boolean isAuthorizationHeaderMissing(List<String> authorizations) {
        return authorizations.isEmpty();
    }

    // JWT 토큰에서 subject (사용자 정보) 추출하는 메소드
    private String getSubjectOf(String jwtToken) {
        return parseJwt(jwtToken).getSubject();
    }

    // JWT 토큰을 파싱하고 Claims 객체를 반환하는 메소드
    private Claims parseJwt(String jwtToken) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey) // SecretKey로 서명 검증
                .build()
                .parseClaimsJws(jwtToken) // JWT 파싱
                .getBody();
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

    // 오류 응답 객체 (코드와 메시지를 포함)
    record ErrorResponse(int code, String message) {}
}
