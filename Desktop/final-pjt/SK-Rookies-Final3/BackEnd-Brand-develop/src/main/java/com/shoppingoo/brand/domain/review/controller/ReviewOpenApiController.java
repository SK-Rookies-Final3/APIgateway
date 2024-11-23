package com.shoppingoo.brand.domain.review.controller;
import com.shoppingoo.brand.domain.review.dto.ReviewResponse;
import com.shoppingoo.brand.domain.review.service.ReviewService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
@RestController
@RequestMapping("/open-api/brand/review")
public class ReviewOpenApiController {

    private final ReviewService reviewService;

    // 생성자 명시
    public ReviewOpenApiController(ReviewService reviewService) {
        this.reviewService = reviewService;
    }

    @GetMapping("/{productCode}")
    public ResponseEntity<List<ReviewResponse>> getReviewsByProduct(
            @PathVariable("productCode") int productCode) {
        List<ReviewResponse> reviews = reviewService.getReviewsByProductCode(productCode);
        return ResponseEntity.ok(reviews);
    }
}