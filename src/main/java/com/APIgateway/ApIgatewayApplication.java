package com.APIgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication
public class ApIgatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApIgatewayApplication.class, args);
	}

}
