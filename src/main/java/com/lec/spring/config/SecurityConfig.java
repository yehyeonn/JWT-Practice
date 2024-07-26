package com.lec.spring.config;


import com.lec.spring.jwt.JWTUtil;
import com.lec.spring.jwt.LoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity(debug = true)    // 요청 시 Security Filter Chain 의 동작확인 출력
//@EnableWebSecurity                    // 스프링 시큐리티 활성화 + 웹 보안 설정 구성
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;  // 빈이라 자동 주입

    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }   // 여기까지가 ppt 4pg


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf disable
        http.csrf((auth) -> auth.disable());    // 그냥 로그인 된다. 왜? filter 1도 없어서

        // 웹서비스에서 사용할 수 있는 여러 인증 방법들...
        // 폼 인증, Http basic 인증, OAuth2 인증, JWT 인증 등이 있음.
        // 이번 예제에선 JWT 인증을 사용할 것이므로
        // Form 인증방식과 http basic 인증방식은 disable 시켜야 한다.

        // Form 인증방식 disable. API 서버이기 때문에(서버사이드랜더링이 아니다!)
        http.formLogin((auth) -> auth.disable());

        // Http basic 인증방식 disable. Http basic 은 header 에 담아 보냄 => 보안성 좋지 않음
        http.httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/member").hasAnyRole("MEMBER", "ADMIN")
                        .anyRequest().permitAll()
                );

        // JWT 를 위한 세션 설정(비활성화)
        http
                .sessionManagement((session) -> session
                        // JWT를 통한 인증/인가를 위해서 세션을 STATELESS 상태로 설정한다
                        // request 가 들어오면 세션을 생성했다가.  request 가 다 처리 되면 세션을 삭제하게 된다
                        //  명심! request 처리전까지는 세션이 존재하는 거구. 이 세션에는 SecurityContextHolder 에 인증정보가 있는 것이다.
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //필터 추가 LoginFilter()는 AuthenticationManager 인자를 받음
        // authenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        // .addFilterAt(필터, 삽일할 위치)
        //   LoginFilter 를 SecurityFilter Chain 의 UsernamePasswordAuthenticationFilter 위치에 삽입 (그 위치를 replace 하게된다!)
        http                                    // Bean 에 Bean 주입
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil),
                        UsernamePasswordAuthenticationFilter.class);        // 이 위치에 넣는다.


        return http.build();    // .build 하면 SecurityFilterCain 만들어냄
    }
}
