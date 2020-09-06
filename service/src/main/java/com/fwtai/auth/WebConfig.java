package com.fwtai.auth;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * WebMvc配置器|Bean配置
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-02-23 17:47
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
*/
@Configuration
public class WebConfig implements WebMvcConfigurer{

    @Override
    public void addCorsMappings(final CorsRegistry registry) {
        registry.addMapping("/**")
            .allowedOrigins("http://api.fwtai.com","http://192.168.3.108")
            .allowCredentials(true)
            .allowedMethods("*")
            .allowedHeaders("*")
            .maxAge(7200L);
    }
}