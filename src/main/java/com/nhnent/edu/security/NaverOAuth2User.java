package com.nhnent.edu.security;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

// TODO : #3 Naver UserInfo 응답 결과에 매칭되는 OAuth2User 확장 클래스.
public class NaverOAuth2User implements OAuth2User, UserDetails {
    @Getter
    @Setter
    private String resultcode;

    @Getter
    @Setter
    private String message;

    @Getter
    @Setter
    private Map<String, Object> response;


    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return (String) response.get("name");
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return response;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new OAuth2UserAuthority("ROLE_MEMBER", response));
    }

    @Override
    public String getName() {
        return (String) response.get("name");
    }

}
