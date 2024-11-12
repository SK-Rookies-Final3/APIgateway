package com.APIgateway.config;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CustomGatewayConfig {

    @Bean
    public GatewayFilter customFilter() {
        return (exchange, chain) -> {
            exchange.getRequest().mutate().header("X-User-Id", "user_id_value").build();
            return chain.filter(exchange);
        };
    }
}


