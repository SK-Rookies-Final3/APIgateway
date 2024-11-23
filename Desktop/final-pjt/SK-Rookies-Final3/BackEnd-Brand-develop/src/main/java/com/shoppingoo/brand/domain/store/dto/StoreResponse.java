package com.shoppingoo.brand.domain.store.dto;

import jakarta.persistence.Column;
import lombok.*;

import java.sql.Timestamp;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
public class StoreResponse {

    private int id;

    private int userId;

    private String name;

    private int licenseNumber;

    private int status;

    private Timestamp registeredAt;




}
