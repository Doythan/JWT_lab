package com.pharmacy.spring_jwt.service;

import com.pharmacy.spring_jwt.dto.AuthRequest;
import com.pharmacy.spring_jwt.dto.AuthResponse;
import com.pharmacy.spring_jwt.dto.SignupRequest;
import com.pharmacy.spring_jwt.dto.TokenRefreshRequest;
import com.pharmacy.spring_jwt.entity.RefreshToken;
import com.pharmacy.spring_jwt.entity.User;
import com.pharmacy.spring_jwt.jwt.JwtTokenProvider;
import com.pharmacy.spring_jwt.repository.RefreshTokenRepository;
import com.pharmacy.spring_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    
    @Value("${jwt.refresh-token-validity}")
    private long refreshTokenValidity;
    
    // 회원가입
    @Transactional
    public String signup(SignupRequest request) {
        // 중복 체크
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("이미 존재하는 사용자명입니다.");
        }
        
        // 사용자 생성
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))  // 비밀번호 암호화
                .name(request.getName())
                .email(request.getEmail())
                .role(User.Role.ROLE_USER)  // 기본 권한
                .build();
        
        userRepository.save(user);
        return "회원가입 성공";
    }
    
    // 로그인
    @Transactional
    public AuthResponse login(AuthRequest request) {
        // 사용자 조회
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        // 비밀번호 확인
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }
        
        // Access Token 생성
        String accessToken = jwtTokenProvider.createAccessToken(
                user.getUsername(), 
                user.getRole().name()
        );
        
        // Refresh Token 생성
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getUsername());
        
        // Refresh Token DB에 저장 (기존 토큰 삭제 후)
        refreshTokenRepository.deleteByUserId(user.getId());
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .userId(user.getId())
                .token(refreshToken)
                .expiryDate(System.currentTimeMillis() + refreshTokenValidity)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);
        
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .role(user.getRole().name())
                .build();
    }
    
    // Access Token 재발급
    @Transactional
    public AuthResponse refreshAccessToken(TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();
        
        // Refresh Token 유효성 검증
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new RuntimeException("유효하지 않은 Refresh Token입니다.");
        }
        
        // DB에서 Refresh Token 조회
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh Token을 찾을 수 없습니다."));
        
        // 만료 체크
        if (storedToken.isExpired()) {
            refreshTokenRepository.delete(storedToken);
            throw new RuntimeException("Refresh Token이 만료되었습니다. 다시 로그인해주세요.");
        }
        
        // 사용자 조회
        User user = userRepository.findById(storedToken.getUserId())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        // 새로운 Access Token 생성
        String newAccessToken = jwtTokenProvider.createAccessToken(
                user.getUsername(), 
                user.getRole().name()
        );
        
        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)  // Refresh Token은 그대로
                .username(user.getUsername())
                .role(user.getRole().name())
                .build();
    }
}