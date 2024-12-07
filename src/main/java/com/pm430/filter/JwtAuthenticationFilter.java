package com.pm430.filter;

import com.pm430.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * JWT 인증 처리를 위한 필터
 * 모든 요청에 대해 JWT 토큰을 검증합니다.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // JWT 유틸리티 클래스 의존성 주입
    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    /**
     * JWT 토큰 기반 인증 처리
     * 모든 요청에 대해 실행되는 필터 메서드
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 요청 헤더에서 JWT 토큰 추출
        String token = getTokenFromRequest(request);

        // 토큰 발급 요청의 경우 인증 없이 통과
        if (request.getRequestURI().equals("/api/token")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 검증 및 처리
        if (token != null && jwtUtil.validateToken(token)) {
            // 토큰에서 사용자 이름 추출
            String username = jwtUtil.getUsernameFromToken(token);

            // 사용자 권한 설정
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            // 사용자 이름이 'admin'인 경우 관리자 권한 부여
            if ("admin".equals(username)) {
                authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }
            // 기본 사용자 권한 부여
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            // 인증 정보 생성
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            username,  // 토큰에서 추출한 사용자 이름 사용
                            null,      // 자격증명(비밀번호 등)은 필요없음
                            authorities  // 설정된 권한 목록
                    );

            // SecurityContext에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } else {
            // 유효하지 않은 토큰인 경우 401 Unauthorized 응답
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
        }
    }

    /**
     * HTTP 요청 헤더에서 JWT 토큰 추출
     *
     * @param request HTTP 요청
     * @return JWT 토큰 (없는 경우 null)
     */
    private String getTokenFromRequest(HttpServletRequest request) {
        // Authorization 헤더에서 토큰 추출
        String bearerToken = request.getHeader("Authorization");
        // Bearer 토큰 형식 확인 및 토큰 부분만 추출
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);  // "Bearer " 부분을 제외한 실제 토큰 반환
        }
        return null;
    }
}