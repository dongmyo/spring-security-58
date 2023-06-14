package com.nhnent.edu.security;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.OAuth2User;
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
                .clientRegistrationRepository(clientRegistrationRepository())
                .authorizedClientService(authorizedClientService())
                .authorizationEndpoint()
                    .authorizationRequestResolver(customAuthorizationRequestResolver())
                    .and()
                .userInfoEndpoint()
                    .userService(oauth2UserService())
                    .and()
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
        return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("payco")
            .clientId("3RDU4G5NI_cxk4VNvSI7")
            .clientSecret("fxVFAe2HjN98DOyrV6kyJVHD")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://alpha-id.payco.com/oauth2.0/authorize")
            .tokenUri("https://alpha-id.payco.com/oauth2.0/token")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .userInfoUri("https://dev-apis.krp.toastoven.net/payco/friends/getMemberProfileByFriendsToken.json")
            .userInfoAuthenticationMethod(AuthenticationMethod.FORM)
            .build());
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    public CustomAuthorizationRequestResolver customAuthorizationRequestResolver() {
        return new CustomAuthorizationRequestResolver(clientRegistrationRepository());
    }

    @SuppressWarnings("deprecation")
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        // TODO : #1 DefaultOAuth2UserService 대신 CustomUserTypesOAuth2UserService 사용.
        //        PAYCO ID UserInfo 응답 결과를 지원하는 OAuth2User 확장 클래스 PaycoOAuth2User 정보를 생성자에 전달.
        Map<String, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();
        customUserTypes.put("payco", PaycoOAuth2User.class);

        CustomUserTypesOAuth2UserService oauth2UserService = new CustomUserTypesOAuth2UserService(customUserTypes);
        oauth2UserService.setRequestEntityConverter(requestEntityConverter());

        return oauth2UserService;
    }

    @Bean
    public CustomRequestEntityConverter requestEntityConverter() {
        return new CustomRequestEntityConverter();
    }

}
