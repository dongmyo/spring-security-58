package com.nhnent.edu.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@Configuration
public class SecurityConfig {
    // TODO #1: Security 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(r ->
            r.requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/private-project/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MEMBER")
                .requestMatchers("/project/**").authenticated()
                .anyRequest().permitAll());

        http.requiresChannel(c ->
                c.requestMatchers("/admin/**").requiresSecure()
                    .requestMatchers("/private-project/**").requiresSecure()
                    .requestMatchers("/project/**").requiresSecure()
                    .anyRequest().requiresInsecure());

        http.formLogin(l -> l.loginPage("/login/form")
            .loginProcessingUrl("/login/process")
            .usernameParameter("id")
            .passwordParameter("pwd")
            .successHandler(new CustomLoginSuccessHandler()));

        http.logout(o -> o.logoutUrl("/auth/logout")
            .deleteCookies("SESSION")
            .invalidateHttpSession(true));

        http.headers(h -> h.defaultsDisabled()
            .frameOptions(f -> f.sameOrigin())
            .contentTypeOptions(c -> c.disable())
            .xssProtection(x -> x.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)));

        http.csrf(c -> c.disable());

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(CustomUserDetailsService customUserDetailsService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customUserDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());

        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Sha256PasswordEncoder();
    }

}
