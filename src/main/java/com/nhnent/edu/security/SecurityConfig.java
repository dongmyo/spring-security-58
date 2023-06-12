package com.nhnent.edu.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            // TODO #1: 웹 요청 ACL 스프링 표현식
            .authorizeHttpRequests()
                .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/private-project/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MEMBER")
                .requestMatchers("/project/**").authenticated()
                .anyRequest().permitAll()
                .and()
            // TODO #2: 로그인
            .formLogin()
                .and()
            // TODO #3: 로그아웃
            .logout()
                .and()
            .headers()
                .defaultsDisabled()
                .cacheControl()
                    .and()
                .contentTypeOptions()
                    .and()
                .xssProtection()
                    .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                    .and()
                .httpStrictTransportSecurity()
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                    .and()
                .and()
            .csrf()
                .and()
            .build();
    }

    // TODO #4: InMemoryUserDetailsManager 반환하는 Bean 등록
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withUsername("admin")
            .password("{noop}admin")
            .authorities("ROLE_ADMIN")
            .build();

        UserDetails member = User.withUsername("member")
            .password("{noop}member")
            .authorities("ROLE_MEMBER")
            .build();

        UserDetails guest = User.withUsername("guest")
            .password("{noop}guest")
            .authorities("ROLE_GUEST")
            .build();

        return new InMemoryUserDetailsManager(admin, member, guest);
    }

}
