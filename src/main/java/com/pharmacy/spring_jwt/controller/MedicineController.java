package com.pharmacy.spring_jwt.controller;

import com.pharmacy.spring_jwt.entity.Medicine;
import com.pharmacy.spring_jwt.jwt.JwtTokenProvider;
import com.pharmacy.spring_jwt.service.MedicineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/medicines")
@RequiredArgsConstructor
public class MedicineController {
    
    private final MedicineService medicineService;
    private final JwtTokenProvider jwtTokenProvider;
    
    // 약품 목록 조회 (인증 필요)
    @GetMapping
    public ResponseEntity<?> getAllMedicines(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        
        // 토큰 검증
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("인증 토큰이 필요합니다.");
        }
        
        String token = authHeader.substring(7); // "Bearer " 제거
        
        if (!jwtTokenProvider.validateToken(token)) {
            return ResponseEntity.status(401).body("유효하지 않은 토큰입니다.");
        }
        
        // 토큰에서 사용자 정보 추출 (필요시 사용)
        String username = jwtTokenProvider.getUsername(token);
        String role = jwtTokenProvider.getRole(token);
        
        System.out.println("요청한 사용자: " + username + ", 권한: " + role);
        
        List<Medicine> medicines = medicineService.getAllMedicines();
        return ResponseEntity.ok(medicines);
    }
    
    // 약품 상세 조회 (인증 필요)
    @GetMapping("/{id}")
    public ResponseEntity<?> getMedicineById(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        
        // 토큰 검증
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("인증 토큰이 필요합니다.");
        }
        
        String token = authHeader.substring(7);
        
        if (!jwtTokenProvider.validateToken(token)) {
            return ResponseEntity.status(401).body("유효하지 않은 토큰입니다.");
        }
        
        Medicine medicine = medicineService.getMedicineById(id);
        return ResponseEntity.ok(medicine);
    }
}