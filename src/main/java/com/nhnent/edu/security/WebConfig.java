package com.nhnent.edu.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");
        registry.addViewController("/admin/**").setViewName("admin");
        registry.addViewController("/project/**").setViewName("project");
        registry.addViewController("/private-project/**").setViewName("private-project");
        registry.addViewController("/login/form").setViewName("login");
        // TODO #13: `/error/403` 요청 시 `/WEB-INF/views/error403.html` view template 응답하도록 설정.
        registry.addViewController("/error/403").setViewName("error403");
        registry.addViewController("/logout").setViewName("logout");
        registry.addRedirectViewController("/redirect-index", "/");
    }

}
