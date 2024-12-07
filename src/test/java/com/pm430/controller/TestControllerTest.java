package com.pm430.controller;

import com.pm430.util.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 컨트롤러 통합 테스트
 */
@SpringBootTest
@AutoConfigureMockMvc
class TestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtil jwtUtil;

    @Test
    @DisplayName("토큰 발급 테스트 - 성공 케이스")
    void getToken_WithValidCredentials_ShouldReturnToken() throws Exception {
        // when & then
        mockMvc.perform(post("/api/token")
                        .param("username", "test")
                        .param("password", "test"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(emptyString())));
    }

    @Test
    @DisplayName("토큰 발급 테스트 - 실패 케이스")
    void getToken_WithInvalidCredentials_ShouldReturn401() throws Exception {
        // when & then
        mockMvc.perform(post("/api/token")
                        .param("username", "wrong")
                        .param("password", "wrong"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("API 키 발급 테스트 - 관리자 권한으로 성공")
    void getApiKey_WithAdminToken_ShouldReturnApiKey() throws Exception {
        // given
        Authentication adminAuth = new UsernamePasswordAuthenticationToken("admin", null,
                Arrays.asList(
                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority("ROLE_USER")
                ));
        String adminToken = jwtUtil.generateUserToken(adminAuth);

        // when & then
        mockMvc.perform(post("/api/apikey")
                        .param("companyName", "TestCompany")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().string(not(emptyString())));
    }

    @Test
    @DisplayName("API 키 발급 테스트 - 일반 사용자 권한으로 실패")
    void getApiKey_WithUserToken_ShouldReturn403() throws Exception {
        // given
        Authentication userAuth = new UsernamePasswordAuthenticationToken("test", null,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        String userToken = jwtUtil.generateUserToken(userAuth);

        // when & then
        mockMvc.perform(post("/api/apikey")
                        .param("companyName", "TestCompany")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("보호된 엔드포인트 접근 테스트 - 유효한 토큰")
    void accessProtectedEndpoint_WithValidToken_ShouldSucceed() throws Exception {
        // given
        Authentication auth = new UsernamePasswordAuthenticationToken("test", null,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        String token = jwtUtil.generateUserToken(auth);

        // when & then
        mockMvc.perform(get("/api/hello")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello World"));
    }

    @Test
    @DisplayName("보호된 엔드포인트 접근 테스트 - 토큰 없음")
    void accessProtectedEndpoint_WithoutToken_ShouldFail() throws Exception {
        // when & then
        mockMvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized());
    }
}