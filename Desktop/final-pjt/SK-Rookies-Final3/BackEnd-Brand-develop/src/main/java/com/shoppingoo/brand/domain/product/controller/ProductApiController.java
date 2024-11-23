package com.shoppingoo.brand.domain.product.controller;

import com.shoppingoo.brand.domain.product.dto.ProductRequest;
import com.shoppingoo.brand.domain.product.dto.ProductResponse;
import com.shoppingoo.brand.domain.product.service.ProductService;
import com.shoppingoo.brand.domain.store.dto.StoreRequest;
import com.shoppingoo.brand.domain.store.dto.StoreResponse;
import io.swagger.v3.oas.annotations.Parameter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/brand/product")
public class ProductApiController {

    private final ProductService productService;

    // 상품 등록
    @PostMapping(value = "/owner/{storeId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ProductResponse> productRegister(
            @PathVariable("storeId") int storeId,
            @RequestHeader("X-User-Id") int userId,
            @RequestPart("productRequest") ProductRequest productRequest,
            @RequestPart("thumbnail") List<MultipartFile> thumbnail, // 썸네일 이미지 파일
            @RequestPart("images") List<MultipartFile> images // 기타 이미지 파일들
    ) {
        ProductResponse productResponse = productService.productRegister(storeId, userId, productRequest, thumbnail, images);
        return ResponseEntity.status(HttpStatus.CREATED).body(productResponse);
    }

    private void triggerFlaskApp(ProductResponse productResponse) {
        RestTemplate restTemplate = new RestTemplate();
        String flaskApiUrl = "http://localhost:5001/api/shorts/search";

        // Flask API로 보낼 데이터
        Map<String, Object> requestData = new HashMap<>();
        requestData.put("product_code", productResponse.getCode());
        requestData.put("product_name", productResponse.getName());

        // HTTP 요청 생성
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(requestData, headers);

        // Flask API 호출
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(flaskApiUrl, requestEntity, String.class);
            System.out.println("Flask API 호출 성공: " + response.getBody());
        } catch (Exception e) {
            System.err.println("Flask API 호출 실패: " + e.getMessage());
        }
    }

    //상품 수정
    @PatchMapping("owner/{storeId}/{productCode}")
    public ResponseEntity<ProductResponse> productUpdate (
            @PathVariable("storeId") int storeId,
            @RequestHeader("X-User-Id") int userId,
            @PathVariable("productCode") int productCode,
            @RequestBody ProductRequest productRequest
    ) {
        ProductResponse productResponse = productService.productUpdate(storeId, userId, productCode, productRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(productResponse);
    }


    //상품 삭제
    @DeleteMapping("owner/{storeId}/{productCode}")
    public ResponseEntity<String> productDelete (
            @PathVariable("storeId") int storeId,
            @RequestHeader("X-User-Id") int userId,
            @PathVariable("productCode") int productCode
    ) {
        productService.productDelete(storeId, userId, productCode);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).body("success");
    }






}
