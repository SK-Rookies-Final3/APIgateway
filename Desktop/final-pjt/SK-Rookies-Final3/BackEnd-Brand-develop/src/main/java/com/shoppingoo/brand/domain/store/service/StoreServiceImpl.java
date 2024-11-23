package com.shoppingoo.brand.domain.store.service;

import com.shoppingoo.brand.db.product.Product;
import com.shoppingoo.brand.db.store.Store;
import com.shoppingoo.brand.db.store.StoreRepository;
import com.shoppingoo.brand.domain.product.dto.ProductResponse;
import com.shoppingoo.brand.domain.store.dto.StatusRequest;
import com.shoppingoo.brand.domain.store.dto.StoreRequest;
import com.shoppingoo.brand.domain.store.dto.StoreResponse;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class StoreServiceImpl implements StoreService {

    private final StoreRepository storeRepository;
    private final ModelMapper modelMapper;

    @Autowired
    public StoreServiceImpl(StoreRepository storeRepository, ModelMapper modelMapper) {
        this.storeRepository = storeRepository;
        this.modelMapper = modelMapper;
    }

    // 가게 등록 요청
    @Override
    public StoreResponse storeRegister(int userId, StoreRequest storeRequest) {
        Store store = modelMapper.map(storeRequest, Store.class);

        // userId 추가
        store.setUserId(userId);
        Store savedStore = storeRepository.save(store);
        return modelMapper.map(savedStore, StoreResponse.class);
    }


    // 전체 조회
    @Override
    public List<StoreResponse> getAllStores() {
        return storeRepository.findAll().stream()
                .map(store -> new StoreResponse(
                        store.getId(),
                        store.getUserId(),
                        store.getName(),
                        store.getLicenseNumber(),
                        store.getStatus(),
                        store.getRegisteredAt()))
                .collect(Collectors.toList());
    }

    // 가게 상세 조회
    @Override
    public StoreResponse getStoreById(int storeId) {
        Store store = storeRepository.findById(storeId).orElse(null);

        if (store == null) {
            throw new RuntimeException("Store not found with id: " + storeId);
        }
        return modelMapper.map(store, StoreResponse.class);
    }

    // 가게 권한 수정
    @Override
    public StoreResponse updateStoreStatus(int storeId, int userId, StatusRequest statusRequest) {
        // 요청에서 받은 storeId를 이용해 가게 정보 조회
        Optional<Store> optionalStore = storeRepository.findById(storeId);

        if (!optionalStore.isPresent()) {
            throw new RuntimeException("Store not found with id " + storeId);
        }

        // 가게 정보 가져오기
        Store store = optionalStore.get();

        store.setStatus(statusRequest.getStatus());
        Store updatedStore = storeRepository.save(store);
        StoreResponse storeResponse = modelMapper.map(updatedStore, StoreResponse.class);

        // 가게 이름 추가
        storeResponse.setName(store.getName());
        return storeResponse;
    }


    // 사용자(owner) 본인의 가게 상태(status) 조회
    @Override
    public int getStoreStatusByUserId(int userId) {
        // userId로 해당 가게 조회
        Store store = storeRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Store not found for user with id: " + userId));

        // 해당 가게의 상태를 반환
        return store.getStatus();
    }

    // 사용자(owner) 본인의 가게 상세 조회
    @Override
    public StoreResponse getStoreByUserId(int userId) {
        Store store = storeRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Store not found for user with id: " + userId));

        return modelMapper.map(store, StoreResponse.class);
    }



}