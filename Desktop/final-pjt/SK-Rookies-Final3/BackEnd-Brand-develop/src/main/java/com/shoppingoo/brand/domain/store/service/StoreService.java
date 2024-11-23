package com.shoppingoo.brand.domain.store.service;

import com.shoppingoo.brand.domain.product.dto.ProductResponse;
import com.shoppingoo.brand.domain.store.dto.StatusRequest;
import com.shoppingoo.brand.domain.store.dto.StoreRequest;
import com.shoppingoo.brand.domain.store.dto.StoreResponse;

import java.util.List;

public interface StoreService {

    StoreResponse storeRegister(int userId, StoreRequest storeRequest);
    List<StoreResponse> getAllStores();
    StoreResponse updateStoreStatus(int storeId, int userId, StatusRequest statusRequest);
    StoreResponse getStoreById(int storeId);
    int getStoreStatusByUserId(int userId);
    StoreResponse getStoreByUserId(int userId);
}
