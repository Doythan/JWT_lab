package com.pharmacy.spring_jwt.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "medicines")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Medicine {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String name;
    
    private String manufacturer;
    
    private Integer stock;
    
    private Integer price;
}