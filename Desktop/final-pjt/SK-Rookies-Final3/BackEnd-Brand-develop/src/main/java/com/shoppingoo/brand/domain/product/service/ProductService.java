package com.shoppingoo.brand.domain.product.service;

import com.shoppingoo.brand.db.product.enums.Category;
import com.shoppingoo.brand.domain.product.dto.ProductRequest;
import com.shoppingoo.brand.domain.product.dto.ProductResponse;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;


public interface ProductService {

    ProductResponse productRegister(int storeId, int userId, ProductRequest productRequest, List<MultipartFile> thumbnailUrl, List<MultipartFile> imageInformation);
    ProductResponse productUpdate(int storeId, int userId, int productCode, ProductRequest productRequest);
    List<ProductResponse> getAllProducts();
    ProductResponse getProductByCode(int productCode);
    List<ProductResponse> getProductByCategory(Category category);
    void productDelete(int storeId, int userId, int productCode);
}
