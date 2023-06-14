package com.nhnent.edu.security;

import javax.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@EnableWebSecurity(debug = true)
@EnableMethodSecurity
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests()
                .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/private-project/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MEMBER")
                .requestMatchers("/project/**").authenticated()
                .requestMatchers("/redirect-index").authenticated()
                .anyRequest().permitAll()
                .and()
            .oauth2Login()
                // TODO : #4 실습 - clientRegistrationRepository와 authorizedClientService를 설정해주세요.
                /* ... */
                .and()
//            .formLogin()
//                .loginPage("/login/form")
//                .loginProcessingUrl("/login/process")
//                .usernameParameter("id")
//                .passwordParameter("pwd")
//                .successHandler(new CustomLoginSuccessHandler())
//                .failureHandler(new CustomLoginFailureHandler())
//                .and()
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
            .csrf()
                .and()
            .addFilterBefore(usernameAdjustingFilter(), UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling()
                .accessDeniedPage("/error/403")
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
        authenticationProvider.setHideUserNotFoundExceptions(false);

        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Sha256PasswordEncoder();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        // TODO : #2 실습 - ClientRegistrationRepository 구현체를 생성하세요.
        //        아래 github() 메서드를 활용하세요.
        return null;
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        // TODO : #3 실습 - OAuth2AuthorizedClientService 구현체를 생성하세요.
        return null;
    }

    private ClientRegistration github() {
        return CommonOAuth2Provider.GITHUB.getBuilder("github")
            .userNameAttributeName("name")
            // TODO #1: 실습 - github에서 생성한 어플리케이션 정보를 참조해서 client_id와 client_secret을 등록하세요.
            .build();
    }

}
