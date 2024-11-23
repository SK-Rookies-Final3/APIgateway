package com.shoppingoo.brand.db.review;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "review")
public class Review {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "review_code", nullable = false) // 기본 키 필드
    private int reviewCode;

    @Column(name = "order_item_id", nullable = false) // 구매 상품 코드
    private int orderItemId;

    @Column(name = "user_id", nullable = false) // 회원 ID
    private int userId;

    @Column(name = "username", nullable = false, length = 50) // 사용자 이름
    private String username;

    @Column(name = "product_code", nullable = false) // 상품 코드
    private int productCode;

    @Column(name = "height", nullable = true) // 키 (NULL 허용)
    private Integer height;

    @Column(name = "weight", nullable = true) // 몸무게 (NULL 허용)
    private Integer weight;

    @Column(name = "product_option", nullable = true, length = 50) // 옵션 (NULL 허용)
    private String option;

    @Column(name = "content", nullable = false, columnDefinition = "TEXT") // 리뷰 내용
    private String content;

    @Column(name = "size", nullable = false, length = 20) // 사이즈
    private String size;

    @Column(name = "star_rating", nullable = false) // 별점
    private int starRating;

    @Column(name = "color", nullable = false, length = 20) // 색상
    private String color;

    @Column(name = "image_url", nullable = true, length = 300) // 이미지 URL (NULL 허용)
    private String imageUrl;

    @Column(name = "review_date", nullable = true) // 작성 날짜 (NULL 허용)
    private LocalDateTime reviewDate;

    // Getter/Setter 제거: Lombok @Data 사용
}