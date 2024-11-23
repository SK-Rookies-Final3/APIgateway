package com.shoppingoo.brand.db.product;

import com.shoppingoo.brand.db.product.enums.Category;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "product")
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "code")
    private int code;

    @Column(name = "store_id", nullable = false)
    private int storeId;

    @Column(name = "name", length = 50, nullable = false)
    private String name;

    @Column(name = "price", nullable = false)
    private int price;

    @Column(name = "stock")
    private int stock;

    @Column(name = "thumbnail", length = 300, nullable = false)
    private List<String> thumbnail;

    @Column(name = "text_information", columnDefinition = "TEXT")
    private String textInformation;

    // 이미지 정보를 List로 저장하기 위해 @ElementCollection을 사용
    @ElementCollection
    @CollectionTable(name = "product_images", joinColumns = @JoinColumn(name = "product_code"))
    @Column(name = "images", length = 300)
    private List<String> images;

    @Column(name = "category", length = 50, nullable = false)
    private Category category;

    @Column(name = "color", length = 20)
    private String color;

    @Column(name = "clothes_size", length = 20)
    private String clothesSize;

    @Column(name = "shoes_size", length = 20)
    private String shoesSize;
}
