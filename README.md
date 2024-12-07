# Spring Security JWT Example

Spring Security와 JWT를 사용한 API 인증 예제 프로젝트입니다.

## 기능
- JWT 기반 사용자 인증
- 장기 사용 가능한 API 키 발급
- Role 기반 권한 관리
- 보호된 API 엔드포인트

## 기술 스택
- Spring Boot
- Spring Security
- JWT (JSON Web Token)
- JUnit 5

## 프로젝트 설정

### 1. 의존성
```gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
}
```

### 2. 애플리케이션 설정
application.properties에 다음 설정을 추가하세요:
```properties
# 스프링 시큐리티 디버그 모드 활성화
logging.level.org.springframework.security=DEBUG
```

## API 사용법

### 1. 사용자 인증 및 토큰 발급

#### Admin 토큰 발급
```bash
curl -X POST 'http://localhost:8080/api/token?username=admin&password=admin123'
```

### 2. API 키 발급 (Admin 권한 필요)
```bash
curl -X POST \
  'http://localhost:8080/api/apikey?companyName=TestCompany' \
  -H 'Authorization: Bearer {admin-token}'
```

### 3. 보호된 API 호출
```bash
curl -X GET \
  'http://localhost:8080/api/hello' \
  -H 'Authorization: Bearer {api-key}'
```

## 테스트 계정
1. 관리자 계정
    - Username: admin
    - Password: admin123
    - Role: ADMIN, USER

2. 일반 사용자 계정
    - Username: test
    - Password: test
    - Role: USER

## 토큰 종류
1. 일반 사용자 토큰
    - 유효기간: 30분
    - 용도: 일반적인 API 호출

2. API 키
    - 유효기간: 10년
    - 용도: 외부 시스템 연동
    - 발급 권한: ADMIN만 가능

## 주의사항
- 실제 운영 환경에서는 반드시 다음 사항을 고려해야 합니다:
    - 사용자 정보 DB 연동
    - 토큰 암호화 키 안전한 관리
    - API 키 모니터링 및 관리 기능 구현
    - 적절한 예외 처리
    - 로깅 및 모니터링 구현

## 프로젝트 구조
```
src/
├── main/
│   └── java/
│       └── com/example/jwt/
│           ├── config/
│           │   └── SecurityConfig.java
│           ├── filter/
│           │   └── JwtAuthenticationFilter.java
│           ├── util/
│           │   └── JwtUtil.java
│           └── controller/
│               └── TestController.java
└── test/
    └── java/
        └── com/example/jwt/
            ├── util/
            │   └── JwtUtilTest.java
            └── controller/
                └── TestControllerIntegrationTest.java
```

## 라이선스
이 프로젝트는 MIT 라이선스를 따릅니다.