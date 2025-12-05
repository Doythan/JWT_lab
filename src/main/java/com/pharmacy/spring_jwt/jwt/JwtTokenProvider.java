package com.pharmacy.spring_jwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtTokenProvider {
    
    private final SecretKey secretKey;
    private final long accessTokenValidity;
    private final long refreshTokenValidity;
    
    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-validity}") long accessTokenValidity,
            @Value("${jwt.refresh-token-validity}") long refreshTokenValidity) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }
    
    // Access Token 생성
    public String createAccessToken(String username, String role) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenValidity);
        
        return Jwts.builder()
                .subject(username)  // 토큰의 주인
                .claim("role", role)  // 권한 정보
                .issuedAt(now)  // 발급 시간
                .expiration(validity)  // 만료 시간
                .signWith(secretKey)  // 서명
                .compact();
    }
    
    // Refresh Token 생성
    public String createRefreshToken(String username) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + refreshTokenValidity);
        
        return Jwts.builder()
                .subject(username)
                .issuedAt(now)
                .expiration(validity)
                .signWith(secretKey)
                .compact();
    }
    
    // 토큰에서 username 추출
    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }
    
    // 토큰에서 role 추출
    public String getRole(String token) {
        return getClaims(token).get("role", String.class);
    }
    
    // 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    
    // 토큰 파싱해서 Claims 가져오기
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}