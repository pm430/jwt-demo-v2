package com.pm430.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
/**
 * JWT 토큰 생성 및 검증을 위한 유틸리티 클래스
 */
@Component
public class JwtUtil {
    // JWT 서명을 위한 키
    private Key key;

    /**
     * 컴포넌트 초기화 시 보안 키 생성
     */
    @PostConstruct  // 빈 생성 후 초기화 수행
    public void init() {
        // HS256 알고리즘을 위한 보안 키 생성
        key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    /**
     * JWT 토큰 생성
     *
     * @param authentication 인증 정보
     * @return 생성된 JWT 토큰
     */
    public String generateToken(Authentication authentication) {
        return Jwts.builder()
                .setSubject(authentication.getName())  // 사용자 이름을 토큰의 제목으로 설정
                .setIssuedAt(new Date())  // 토큰 발행 시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))  // 30분 후 만료
                .signWith(key)  // 생성된 키로 토큰 서명
                .compact();  // 토큰 생성 및 직렬화
    }

    /**
     * JWT 토큰 유효성 검증
     *
     * @param token 검증할 토큰
     * @return 토큰 유효성 여부
     */
    public boolean validateToken(String token) {
        try {
            // 토큰 파싱 및 서명 검증
            Jwts.parserBuilder()
                    .setSigningKey(key)  // 검증을 위한 키 설정
                    .build()  // JWT 파서 생성
                    .parseClaimsJws(token);  // 토큰 파싱 및 검증
            return true;  // 파싱 성공시 유효한 토큰
        } catch (Exception e) {
            return false;  // 파싱 실패시 유효하지 않은 토큰
        }
    }

    /**
     * 토큰에서 사용자 이름 추출
     *
     * @param token JWT 토큰
     * @return 사용자 이름
     */
    public String getUsernameFromToken(String token) {
        // 토큰에서 클레임(내용) 추출
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();  // 토큰의 내용(payload) 추출

        return claims.getSubject();  // 사용자 이름 반환
    }
}