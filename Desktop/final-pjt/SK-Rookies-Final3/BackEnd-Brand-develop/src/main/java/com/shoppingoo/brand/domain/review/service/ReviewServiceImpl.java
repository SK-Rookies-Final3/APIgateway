package com.shoppingoo.brand.domain.review.service;
import com.shoppingoo.brand.db.product.Product;
import com.shoppingoo.brand.db.product.ProductRepository;
import com.shoppingoo.brand.db.review.Review;
import com.shoppingoo.brand.db.review.ReviewRepository;
import com.shoppingoo.brand.domain.review.dto.ReviewRequest;
import com.shoppingoo.brand.domain.review.dto.ReviewResponse;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
@Service
public class ReviewServiceImpl implements ReviewService {

    private final ReviewRepository reviewRepository;
    private final ProductRepository productRepository;
    private final ModelMapper modelMapper;

    @Autowired
    public ReviewServiceImpl(ReviewRepository reviewRepository, ProductRepository productRepository, ModelMapper modelMapper) {
        this.reviewRepository = reviewRepository;
        this.productRepository = productRepository;
        this.modelMapper = modelMapper;
    }

    @Override
    public ReviewResponse reviewRegister(int productCode, int userId, ReviewRequest reviewRequest) {
        Product product = productRepository.findById(productCode)
                .orElseThrow(() -> new RuntimeException("Product not found with code: " + productCode));

        Review review = modelMapper.map(reviewRequest, Review.class);
        review.setProductCode(productCode);
        review.setUserId(userId);
        review.setReviewDate(LocalDateTime.now());

        Review savedReview = reviewRepository.save(review);
        return modelMapper.map(savedReview, ReviewResponse.class);
    }

    @Override
    public List<ReviewResponse> getReviewsByProductCode(int productCode) {
        List<Review> reviews = reviewRepository.findByProductCode(productCode);
        return reviews.stream()
                .map(review -> modelMapper.map(review, ReviewResponse.class))
                .collect(Collectors.toList());
    }

    @Override
    public void reviewDelete(int reviewId, int userId) {
        Review review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new RuntimeException("Review not found with id: " + reviewId));

        if (review.getUserId() != userId) {
            throw new RuntimeException("You do not have permission to delete this review");
        }

        reviewRepository.delete(review);
    }
}