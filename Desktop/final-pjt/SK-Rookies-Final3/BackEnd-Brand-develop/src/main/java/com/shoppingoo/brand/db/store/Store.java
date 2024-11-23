package com.shoppingoo.brand.db.store;

import jakarta.persistence.*;
import lombok.*;

import java.sql.Timestamp;

@Data
@Entity
@Table(name = "store")
@NoArgsConstructor
@AllArgsConstructor
public class Store {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // AUTO_INCREMENT를 사용
    private int id;

    @Column(name = "user_id", nullable = false)
    private int userId;

    @Column(name = "name", nullable = false, length = 50)
    private String name;

    @Column(name = "license_number", nullable = false, length = 50)
    private int licenseNumber;

    @Column(name = "status", nullable = false)
    private int status;

    @Column(name = "registered_at")
    private Timestamp registeredAt;

}
