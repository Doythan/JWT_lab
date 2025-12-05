package com.pharmacy.spring_jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {
    
    @GetMapping("/public")
    public String publicEndpoint() {
        return "누구나 접근 가능한 API입니다!";
    }
}