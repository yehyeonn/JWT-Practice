package com.lec.spring.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// Cors 설정하기
@Configuration
public class MvcConfiguration implements WebMvcConfigurer {

    @Value("${cors.allowed-origins}")
    private String[] corsAllowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        corsRegistry
                .addMapping("/**")
                .allowedOrigins(corsAllowedOrigins);    // 어떠한 경로든 yml 에 지정한 경로면 허용해준다는 뜻
    }
}
