package com.nhnent.edu.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

// TODO : #2 PAYCO ID UserInfo 응답 결과에 매칭되는 OAuth2User 확장 클래스.
//        UserDetails interface까지 구현하면 기존 코드와 호환 가능.
public class PaycoOAuth2User implements OAuth2User, UserDetails {
    private Header header;
    private Map<String, Object> memberProfile;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new OAuth2UserAuthority("ROLE_MEMBER", memberProfile));
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return (String) memberProfile.get(getName());
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
        return memberProfile;
    }

    @Override
    public String getName() {
        return "id";
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public Map<String, Object> getMemberProfile() {
        return memberProfile;
    }

    public void setMemberProfile(Map<String, Object> memberProfile) {
        this.memberProfile = memberProfile;
    }


    public static class Header {
        private boolean isSuccessful;
        private int resultCode;
        private String resultMessage;


        @JsonProperty("isSuccessful")
        public boolean isSuccessful() {
            return isSuccessful;
        }

        private void setSuccessful(boolean isSuccessful) {
            this.isSuccessful = isSuccessful;
        }

        public int getResultCode() {
            return resultCode;
        }

        public void setResultCode(int resultCode) {
            this.resultCode = resultCode;
        }

        public String getResultMessage() {
            return resultMessage;
        }

        public void setResultMessage(String resultMessage) {
            this.resultMessage = resultMessage;
        }

    }

}
