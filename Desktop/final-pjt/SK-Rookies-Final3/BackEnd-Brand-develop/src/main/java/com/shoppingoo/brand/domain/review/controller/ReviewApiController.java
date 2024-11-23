package com.shoppingoo.brand.domain.review.controller;

import com.shoppingoo.brand.domain.review.dto.ReviewRequest;
import com.shoppingoo.brand.domain.review.dto.ReviewResponse;
import com.shoppingoo.brand.domain.review.service.ReviewService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/brand/review")
public class ReviewApiController {

    private final ReviewService reviewService;

    // 생성자 명시
    public ReviewApiController(ReviewService reviewService) {
        this.reviewService = reviewService;
    }

    // 리뷰 등록
    @PostMapping("/{productCode}")
    public ResponseEntity<ReviewResponse> createReview(
            @PathVariable("productCode") int productCode,
            @RequestParam("userId") int userId,
            @RequestBody ReviewRequest reviewRequest) {
        ReviewResponse reviewResponse = reviewService.reviewRegister(productCode, userId, reviewRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(reviewResponse);
    }

    // 리뷰 삭제
    @DeleteMapping("/{reviewId}")
    public ResponseEntity<Void> deleteReview(
            @PathVariable("reviewId") int reviewId,
            @RequestParam("userId") int userId) { // userId를 추가로 받음
        reviewService.reviewDelete(reviewId, userId); // userId를 전달
        return ResponseEntity.noContent().build(); // 204 No Content 반환
    }

}