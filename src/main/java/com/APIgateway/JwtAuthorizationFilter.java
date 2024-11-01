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

    @Value("${auth.jwt.key}") // 애플리케이션 속성에서 JWT 비밀 키를 주입
    private String key;

    private final ObjectMapper objectMapper; // JSON 직렬화를 위한 Jackson 객체 매퍼

    private static final String AUTH_TYPE = "Bearer "; // Bearer 토큰의 접두사
    private static final int ERROR_NO_AUTH = 701; // 인증 헤더 없음에 대한 에러 코드
    private static final int ERROR_TOKEN_EXPIRED = 702; // 토큰 만료에 대한 에러 코드
    private static final int ERROR_UNKNOWN = 999; // 일반 에러 코드

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("JwtAuthorizationFilter begin"); // 필터 시작 로그
        try {
            // 요청에서 Authorization 헤더를 가져옴
            List<String> authorizations = getAuthorizations(exchange);

            // Authorization 헤더가 존재하는지 확인
            if (isNotExistsAuthorizationHeader(authorizations)) {
                throw new NotExistsAuthorization(); // 없으면 사용자 정의 예외 던짐
            }

            // Authorization 헤더에서 Bearer 토큰을 찾음
            String authorization = authorizations.stream()
                    .filter(this::isBearerType) // Bearer 타입 필터링
                    .findFirst()
                    .orElseThrow(NotExistsAuthorization::new); // 없으면 예외 던짐

            String jwtToken = parseAuthorizationToken(authorization); // JWT 토큰 파싱
            validateJwtToken(jwtToken); // 토큰의 만료 검증
            // 요청 헤더에 토큰의 주제를 추가하여 이후 처리에 사용
            exchange.getRequest().mutate().header("X-Gateway-Header", getSubjectOf(jwtToken));

            return chain.filter(exchange); // 필터 체인을 계속 진행
        } catch (NotExistsAuthorization e1) {
            return sendErrorResponse(exchange, ERROR_NO_AUTH, e1); // 인증 헤더 없음 처리
        } catch (AccessTokenExpiredException e2) {
            return sendErrorResponse(exchange, ERROR_TOKEN_EXPIRED, e2); // 만료된 토큰 처리
        } catch (Exception e3) {
            return sendErrorResponse(exchange, ERROR_UNKNOWN, e3); // 기타 예외 처리
        }
    }

    private void validateJwtToken(String jwtToken) {
        Claims claims = parseJwt(jwtToken); // JWT에서 클레임 추출
        Date expiration = claims.getExpiration(); // 만료 날짜 가져오기
        if (expiration.before(new Date())) {
            throw new AccessTokenExpiredException(); // 만료되면 예외 던짐
        }
    }

    private Mono<Void> sendErrorResponse(ServerWebExchange exchange, int errorCode, Exception e) {
        try {
            // 에러 코드와 메시지를 포함한 에러 응답 생성
            ErrorResponse errorResponse = new ErrorResponse(errorCode, e.getMessage());
            String errorBody = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(errorResponse); // JSON으로 변환

            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED); // HTTP 상태 설정
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON); // 콘텐츠 타입 설정
            DataBuffer buffer = response.bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8)); // 응답 본문 준비
            return response.writeWith(Flux.just(buffer)); // 응답 작성 및 반환
        } catch (JsonProcessingException ex) {
            throw new RuntimeException(ex); // JSON 처리 예외 발생 시
        }
    }

    private boolean isBearerType(String authorization) {
        return authorization.startsWith(AUTH_TYPE); // "Bearer "로 시작하는지 확인
    }

    private List<String> getAuthorizations(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        List<String> authorizations = request.getHeaders().get(HttpHeaders.AUTHORIZATION); // Authorization 헤더 가져오기
        return authorizations != null ? authorizations : List.of(); // 없으면 빈 리스트 반환
    }

    private String parseAuthorizationToken(String authorization) {
        return authorization.replace(AUTH_TYPE, "").trim(); // "Bearer "를 제거하고 토큰만 추출
    }

    private boolean isNotExistsAuthorizationHeader(List<String> authorizations) {
        return authorizations.isEmpty(); // 리스트가 비어있는지 확인
    }

    private String getSubjectOf(String jwtToken) {
        return parseJwt(jwtToken).getSubject(); // 토큰 클레임에서 주제 가져오기
    }

    private Claims parseJwt(String jwtToken) {
        SecretKey secretKey = secretKey(); // 파싱을 위한 비밀 키 가져오기
        return Jwts.parserBuilder()
                .setSigningKey(secretKey) // 서명 키 설정
                .build()
                .parseClaimsJws(jwtToken) // JWT 파싱
                .getBody(); // 클레임 반환
    }

    private SecretKey secretKey() {
        return Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8)); // 제공된 키로 비밀 키 생성
    }

    // 인증 헤더가 없는 경우를 위한 사용자 정의 예외
    public static class NotExistsAuthorization extends RuntimeException {
        public NotExistsAuthorization() {
            super("Authorization header is missing."); // 에러 메시지
        }
    }

    // 액세스 토큰이 만료된 경우를 위한 사용자 정의 예외
    public static class AccessTokenExpiredException extends RuntimeException {
        public AccessTokenExpiredException() {
            super("Access token is expired."); // 에러 메시지
        }
    }

    // 에러 응답 구조를 나타내는 레코드
    record ErrorResponse(int code, String message) {}
}
