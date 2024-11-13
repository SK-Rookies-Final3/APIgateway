package com.APIgateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

@Component
public class RestTemplateGatewayFilter implements GatewayFilter {

    private final RestTemplate restTemplate;

    public RestTemplateGatewayFilter(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    // 메인 필터
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // 헤더에서 X-User-Id 가져오기
        String userId = exchange.getRequest().getHeaders().getFirst("X-User-Id");

        // RestTemplate을 통해 다른 서비스로 요청 보내기
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-User-Id", userId);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        // 다른 서비스에 GET 요청 보내기
        ResponseEntity<String> response = restTemplate.exchange(
                "http://192.168.0.71:8081/api/store/some-endpoint",  // 다른 서비스의 엔드포인트(테스트용 API입니다)
                HttpMethod.GET,  // 요청 방식
                entity,  // 요청 헤더와 본문 포함
                String.class  // 응답 타입
        );

        // 응답을 클라이언트에게 반환
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(response.getBody().getBytes())));
    }
}
