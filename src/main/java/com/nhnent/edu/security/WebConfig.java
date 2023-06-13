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
        // TODO #7: `/redirect-index`로 접근하면 `/`로 redirect
        registry.addRedirectViewController("/redirect-index", "/");
    }

}
