package com.nhnent.edu.security;

import javax.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
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
                .requestMatchers("/project/**").authenticated()
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .and()
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
            // TODO #3: UsernameAdjustingFilter 를 UsernamePasswordAuthenticationFilter 앞에 추가
            .addFilterBefore(usernameAdjustingFilter(), UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    // TODO #1: username 을 email 형태로 변경
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withUsername("admin@nhn.com")
            .password("{noop}admin")
            .authorities("ROLE_ADMIN")
            .build();

        UserDetails member = User.withUsername("member@nhn.com")
            .password("{noop}member")
            .authorities("ROLE_MEMBER")
            .build();

        UserDetails guest = User.withUsername("guest@nhn.com")
            .password("{noop}guest")
            .authorities("ROLE_GUEST")
            .build();

        return new InMemoryUserDetailsManager(admin, member, guest);
    }

    // TODO #4: UsernameAdjustingFilter 를 빈으로 등록
    @Bean
    public Filter usernameAdjustingFilter() {
        return new UsernameAdjustingFilter("username");
    }

}
