package com.sqber.jwtTest.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CORSConfiguration implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry
                .addMapping("/**").exposedHeaders("Authorization")  //匹配访问的路径
                .allowedMethods("*")           //匹配访问的方法
                .allowedOrigins("*")           //匹配允许跨域访问的源 "http://localhost:8081", "http://localhost:8082"
                .allowedHeaders("*");          //匹配允许头部访问
    }
}