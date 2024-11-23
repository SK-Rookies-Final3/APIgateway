package com.shoppingoo.brand.db.product;

import com.shoppingoo.brand.db.product.enums.Category;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProductRepository extends JpaRepository<Product, Integer> {

    List<Product> findByCategory(Category category);

}