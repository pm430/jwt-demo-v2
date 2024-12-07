package com.pm430.controller;

import com.pm430.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/**
 * API 엔드포인트를 제공하는 컨트롤러
 */
@RestController
@RequestMapping("/api")  // /api로 시작하는 모든 요청을 처리
public class TestController {
    // JWT 유틸리티 클래스 의존성 주입
    private final JwtUtil jwtUtil;
    // 인증 관리자 의존성 주입
    private final AuthenticationManager authenticationManager;

    public TestController(JwtUtil jwtUtil, AuthenticationManager authenticationManager) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    /**
     * JWT 토큰 발급 API
     * 사용자 인증 후 JWT 토큰을 발급합니다.
     *
     * @param username 사용자 이름
     * @param password 비밀번호
     * @return JWT 토큰
     * @throws ResponseStatusException 인증 실패 시 발생
     */
    @PostMapping("/token")
    public String getToken(@RequestParam String username, @RequestParam String password) {
        try {
            // 사용자 인증 시도
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)  // 인증 토큰 생성
            );
            // 인증 성공 시 JWT 토큰 발급
            return jwtUtil.generateUserToken(authentication);
        } catch (BadCredentialsException e) {
            // 인증 실패 시 401 Unauthorized 응답
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
    }

    /**
     * API 키 스타일의 장기 토큰 발급 (관리자만 가능)
     */
    @PostMapping("/apikey")
    @PreAuthorize("hasRole('ADMIN')")  // 관리자만 API 키 발급 가능
    public String generateApiKey(@RequestParam String companyName) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return jwtUtil.generateApiToken(authentication);
    }

    /**
     * 보호된 API 엔드포인트
     * JWT 토큰이 유효한 경우에만 접근 가능합니다.
     *
     * @return 테스트 메시지
     */
    @GetMapping("/hello")
    public String hello() {
        return "Hello World";  // 간단한 테스트 메시지 반환
    }
}