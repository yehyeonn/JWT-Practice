package com.lec.spring.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// jwt 를 다루고 담을 클래스?
// JWT '발급' 및 '검증'
@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm());   // 주어진 secret 을 HS256 로 암호화해서 새로운 키 발급!
    }

    //------------------------------------------------------------------
    // JWT 생성
    // Payload 에 저장될 정보
    // - id, username, role, 생성일, 만료일
    public String createJwt(Long id, String username, String role, Long expiredMs) {    //expiredMs: 남겨둘 시간
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .claim("id", id)
                .issuedAt(new Date(System.currentTimeMillis())) // 생성일
                .expiration(new Date(System.currentTimeMillis() + expiredMs))   // 만료 일시
                .signWith(secretKey)
                .compact(); // 최종적으로 완성
    }

    //------------------------------------------------------------------
    // JWT token 에서 내용 확인
    public Integer getId(String token){
        return Jwts.parser()   // parser 객체 만들기
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)   // token에서
                .getPayload()               // Claims 가져오고
                .get("id", Integer.class);        // 그 중 id 를 가져옴
    }

    public String getUsername(String token) {  // username 확인
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("username", String.class);
    }


    public String getRole(String token) {  // role 확인
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }


    public Boolean isExpired(String token) {  // 만료일 확인
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date());    // 현재 시간보다 이전인지 여부를 확인 해서 만료 됐으면 true 리턴하는 것.
    }





}
