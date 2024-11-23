package com.shoppingoo.brand.db.product.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum Category {
    겉옷("겉옷"),
    상의("상의"),
    하의("하의"),
    치마("치마"),
    신발("신발"),
    모자("모자"),
    가방("가방"),
    장신구("장신구")
    ;

    private String description;
}