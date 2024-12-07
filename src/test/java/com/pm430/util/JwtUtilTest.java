package com.pm430.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JWT 유틸리티 단위 테스트
 */
@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        jwtUtil.init(); // 키 초기화
    }

    @Test
    @DisplayName("일반 사용자 토큰 생성 테스트")
    void generateUserToken_ShouldCreateValidToken() {
        // given
        Authentication authentication = new UsernamePasswordAuthenticationToken("test", null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

        // when
        String token = jwtUtil.generateUserToken(authentication);

        // then
        assertNotNull(token);
        assertTrue(jwtUtil.validateToken(token));
        assertEquals("test", jwtUtil.getUsernameFromToken(token));
    }

    @Test
    @DisplayName("API 토큰 생성 테스트 - 10년 만료")
    void generateApiToken_ShouldCreateLongLivedToken() {
        // given
        Authentication authentication = new UsernamePasswordAuthenticationToken("admin", null, Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER")));

        // when
        String token = jwtUtil.generateApiToken(authentication);

        // then
        assertNotNull(token);
        assertTrue(jwtUtil.validateToken(token));
        assertEquals("admin", jwtUtil.getUsernameFromToken(token));
    }

    @Test
    @DisplayName("만료된 토큰 검증 테스트")
    void validateToken_ShouldReturnFalseForExpiredToken() {
        // given
        Authentication authentication = new UsernamePasswordAuthenticationToken("test", null);
        String token = Jwts.builder().setSubject("test").setIssuedAt(new Date(System.currentTimeMillis() - 1000 * 60 * 60)) // 1시간 전 발급
                .setExpiration(new Date(System.currentTimeMillis() - 1000 * 60 * 30)) // 30분 전 만료
                .signWith(Keys.secretKeyFor(SignatureAlgorithm.HS256)).compact();

        // when & then
        assertFalse(jwtUtil.validateToken(token));
    }
}