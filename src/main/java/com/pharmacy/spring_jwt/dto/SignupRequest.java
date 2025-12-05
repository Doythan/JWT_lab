package com.pharmacy.spring_jwt.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequest {
    private String username;
    private String password;
    private String name;
    private String email;
}