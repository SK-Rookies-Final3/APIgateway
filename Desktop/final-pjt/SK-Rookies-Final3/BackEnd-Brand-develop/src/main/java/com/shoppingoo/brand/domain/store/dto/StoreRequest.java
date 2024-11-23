package com.shoppingoo.brand.domain.store.dto;


import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class StoreRequest {

    @NotNull
    private String name;

    @NotNull
    private int licenseNumber;


}
