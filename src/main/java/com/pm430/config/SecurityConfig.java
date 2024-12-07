package com.pm430.config;

import com.pm430.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
/**
 * Spring Security 설정 클래스
 * JWT 기반의 인증을 위한 보안 설정을 정의합니다.
 */
@Configuration  // 스프링 설정 클래스임을 명시
@EnableWebSecurity  // Spring Security 활성화
public class SecurityConfig {
    // JWT 인증 필터 의존성 주입
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // 생성자 주입 (단일 생성자이므로 @Autowired 생략 가능)
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * Spring Security Filter Chain 설정
     * 보안 필터 체인을 구성하고 각종 보안 설정을 정의합니다.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 보호 기능 비활성화 (REST API는 CSRF 보호가 필요없음)
                .csrf(AbstractHttpConfigurer::disable)
                // 세션 관리 설정
                .sessionManagement(session ->
                        // 세션을 생성하지 않음 (JWT는 세션이 필요없음)
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // HTTP 요청에 대한 접근 권한 설정
                .authorizeHttpRequests(auth ->
                        auth
                                // 토큰 발급 API는 인증 없이 접근 가능
                                .requestMatchers("/api/token").permitAll()
                                // 나머지 모든 요청은 인증 필요
                                .anyRequest().authenticated()
                )
                // HTTP Basic 인증 비활성화
                .httpBasic(AbstractHttpConfigurer::disable)
                // 폼 로그인 비활성화
                .formLogin(AbstractHttpConfigurer::disable)
                // JWT 필터를 UsernamePasswordAuthenticationFilter 앞에 추가
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * 인증 관리자 빈 설정
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * 테스트용 인메모리 사용자 정보 서비스 설정
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // 일반 사용자 계정 생성
        UserDetails user1 = User.builder()
                .username("test")  // 사용자명 설정
                .password(passwordEncoder().encode("test"))  // 비밀번호 암호화하여 설정
                .roles("USER")  // 사용자 권한 설정
                .build();

        // 관리자 계정 생성
        UserDetails user2 = User.builder()
                .username("admin")  // 관리자명 설정
                .password(passwordEncoder().encode("admin123"))  // 비밀번호 암호화하여 설정
                .roles("ADMIN")  // 관리자 권한 설정
                .build();

        // 인메모리 사용자 정보 서비스 생성
        return new InMemoryUserDetailsManager(user1, user2);
    }

    /**
     * 비밀번호 암호화를 위한 인코더 설정
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt 암호화 방식 사용
        return new BCryptPasswordEncoder();
    }
}