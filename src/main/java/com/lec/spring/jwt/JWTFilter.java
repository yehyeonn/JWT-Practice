package com.lec.spring.jwt;

import com.lec.spring.config.PrincipalDetails;
import com.lec.spring.domain.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 스프링에서, 디스패처 서블릿이 서블릿 컨테이너 앞에서 모든 요청을 컨트롤러에 전달한다.
 * 서블릿은 요청마다 서블릿을 생성하여 메모리에 저장한 뒤 같은 클라이언트의 요청이 들어올 경우
 * 생성해둔 서블릿 객체를 재활용한다.
 * 그런데 만약 서블릿이 다른 서블릿으로 dispatch하게 되면,
 * 다른 서블릿 앞단에서 filter chain을 한번 더 거치게 된다.
 * 이 차이때문에 OncePerRequestFilter를 사용한다.
 */
public class JWTFilter extends OncePerRequestFilter {   // Bean 아니다!

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("doFilterInternal() 호출");

        // request 에서 Authorization 헤더를 찾음(JWT 있는지)
        String authorization = request.getHeader("Authorization");  // 헤더 없으면 null 리턴

        // Authorization 헤더 검증
        if(authorization == null || !authorization.startsWith("Bearer ")){
            // JWT 가 없다!
            System.out.println("\tJWT도 없고 유인아도 없고...");
            filterChain.doFilter(request, response);    // 리턴하기 전에 다음 필터에 넘기고 종료!
            return;
        }
        // 있다면 "Bearer " 부분 제거 후 JWT 토큰 획득
        String token = authorization.split(" ")[1];

        // 토큰 소멸 시간 검증. 이미 소멸됐다면 쓰면 안되기 때문
        if(jwtUtil.isExpired(token)) {
            System.out.println("\ttoken expired");
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰에서 id, username, role 획득
        Long id = jwtUtil.getId(token);
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // User 생성하여 로그인 진행
        User user = User.builder()
                .id(id)
                .username(username)
                .password("temppassword")   // 임시 비밀번호 (어차피 Session 에 저장하는 용도. 이미 회원가입이 되어있어 정보가 있음)
                .role(role)
                .build();

        // UserDetails 에 User 담아 생성
        PrincipalDetails userDetails = new PrincipalDetails(user);

        // 스프링 시큐리티 인증 토큰 생성 => Authentication
        Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());   // Authentication 리턴함

        // 세션에 위 Authentication 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 다음 필터로 전달
        filterChain.doFilter(request, response);
    }
}
