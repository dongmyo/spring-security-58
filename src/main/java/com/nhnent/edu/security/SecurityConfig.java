package com.nhnent.edu.security;

import javax.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests()
                .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/private-project/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MEMBER")
                /* TODO #1: 실습 - 공개 프로젝트 URL은 (`/project/**`) 로그인한 경우에는 누구나 접근 가능하도록 설정해주세요. */
                /* ... */
                .requestMatchers("/redirect-index").authenticated()
                .anyRequest().permitAll()
                .and()
            .formLogin()
                // TODO #2: 로그인 페이지 커스터마이징
                .loginPage("/login/form")
                .loginProcessingUrl("/login/process")
                .usernameParameter("id")
                .passwordParameter("pwd")
                .successHandler(new CustomLoginSuccessHandler())
                // TODO #5: 실습 - 로그인 실패 핸들러를 설정해주세요.
                /* ... */
                .and()
            .logout()
                .logoutSuccessUrl("/login/form?logout")
                .invalidateHttpSession(true)
                .deleteCookies("SESSION")
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
                .frameOptions()
                    .sameOrigin()
                .and()
            // TODO #3: Csrf 필터가 설정되어 있음
            .csrf()
                .and()
            .addFilterBefore(usernameAdjustingFilter(), UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling()
                /* TODO #12: 실습 - custom 403 에러 페이지(`/error/403`)를 설정해주세요. */
                /* ... */
                .and()
            .build();
    }

    @Bean
    public Filter usernameAdjustingFilter() {
        return new UsernameAdjustingFilter("username");
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(CustomUserDetailsService customUserDetailsService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customUserDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        // TODO #7: UsernameNotFoundException, BadCredentialsException 구분하도록 설정.
        authenticationProvider.setHideUserNotFoundExceptions(false);

        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Sha256PasswordEncoder();
    }

}
