package com.shoppingoo.brand.domain.store.controller;


import com.shoppingoo.brand.domain.store.dto.StoreResponse;
import com.shoppingoo.brand.domain.store.service.StoreService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/open-api/brand/store")
public class StoreOpenApiController {

    private final StoreService storeService;

    // 전체 조회
    @GetMapping("/")
    public ResponseEntity<List<StoreResponse>> getAllStores() {

        List<StoreResponse> storeResponseList = storeService.getAllStores();
        return ResponseEntity.ok(storeResponseList); // 응답 반환

    }

    // 가게 상세 조회
    @GetMapping("/{storeId}")
    public ResponseEntity<StoreResponse> getStoreById(@PathVariable int storeId) {

        StoreResponse storeResponse = storeService.getStoreById(storeId);
        if (storeResponse != null) {
            return ResponseEntity.ok(storeResponse);
        } else {
            return ResponseEntity.notFound().build();
        }
    }



}
