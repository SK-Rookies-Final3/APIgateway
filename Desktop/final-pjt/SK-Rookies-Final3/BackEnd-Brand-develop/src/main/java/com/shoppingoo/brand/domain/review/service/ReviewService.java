package com.shoppingoo.brand.domain.review.service;

import com.shoppingoo.brand.domain.review.dto.ReviewRequest;
import com.shoppingoo.brand.domain.review.dto.ReviewResponse;

import java.util.List;

public interface ReviewService {
    ReviewResponse reviewRegister(int productCode, int userId, ReviewRequest reviewRequest);
    List<ReviewResponse> getReviewsByProductCode(int productCode);
    void reviewDelete(int reviewId, int userId); // 사용자 ID를 포함하는 수정된 메서드 시그니처
}
