package com.shoppingoo.brand.domain.review.dto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ReviewRequest {
    private int orderItemId;
    private int productCode;
    private int userId;
    private int height;
    private int weight;
    private String username;
    private String option;
    private String content;
    private String size;
    private int starRating;
    private String color;
    private String imageUrl;
}