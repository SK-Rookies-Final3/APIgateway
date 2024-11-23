package com.shoppingoo.brand.domain.store.controller;

import com.shoppingoo.brand.domain.store.dto.StatusRequest;
import com.shoppingoo.brand.domain.store.dto.StoreRequest;
import com.shoppingoo.brand.domain.store.dto.StoreResponse;
import com.shoppingoo.brand.domain.store.service.StoreService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/brand/store")
public class StoreApiController {

    private final StoreService storeService;

    // 가게 등록 요청(role == owner)
    @PostMapping("/owner/register")
    public ResponseEntity<StoreResponse> storeRegister(
            @RequestBody StoreRequest storeRequest,
            @RequestHeader("X-User-Id") int userId
    ) {
        StoreResponse storeResponse = storeService.storeRegister(userId, storeRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(storeResponse);
    }


    // 가게 권한 수정(role == master)
    @PatchMapping("/master/{storeId}/status")
    public ResponseEntity<StoreResponse> updateStoreStatus(
            @PathVariable int storeId,
            @RequestBody StatusRequest statusRequest,
            @RequestHeader("X-User-Id") int userId
            ) {
        StoreResponse storeResponse = storeService.updateStoreStatus(storeId, userId, statusRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(storeResponse);
    }

    // 사용자(owner) 본인의 가게 상태(status) 조회
    @GetMapping("owner/status/{userId}")
    public ResponseEntity<Integer> getStoreStatus(
            @RequestHeader("X-User-Id") int userId) {
        int status = storeService.getStoreStatusByUserId(userId);
        return ResponseEntity.ok(status);
    }

    // 사용자(owner) 본인의 가게 상세 조회
    @GetMapping("owner")
    public ResponseEntity<StoreResponse> getStoreByUserId(
            @RequestHeader("X-User-Id") int userId) {
        StoreResponse storeResponse = storeService.getStoreByUserId(userId);
        if (storeResponse != null) {
            return ResponseEntity.ok(storeResponse);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

}

