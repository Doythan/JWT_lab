package com.pharmacy.spring_jwt.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(nullable = false)
    private String password;  // 암호화된 비밀번호 저장
    
    @Column(nullable = false)
    private String name;
    
    private String email;
    
    @Enumerated(EnumType.STRING)
    private Role role;
    
    public enum Role {
        ROLE_USER, ROLE_ADMIN
    }
}