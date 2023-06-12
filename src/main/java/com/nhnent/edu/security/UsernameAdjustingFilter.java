package com.nhnent.edu.security;

import java.io.IOException;
import java.util.Objects;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

// TODO #2: request parameter 로 전달되는 username 을 조정하는 필터
public class UsernameAdjustingFilter extends OncePerRequestFilter {
    private final String usernameParameter;
    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/login", "POST");


    public UsernameAdjustingFilter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest requestToUse = request;

        if (requestMatcher.matches(request)) {
            requestToUse = new HttpServletRequestWrapper(request) {
                @Override
                public String getParameter(String name) {
                    if (Objects.equals(name, usernameParameter)) {
                        String username = super.getParameter(name);
                        if (Objects.nonNull(username) && !username.endsWith("@nhn.com")) {
                            return username + "@nhn.com";
                        }
                    }

                    return super.getParameter(name);
                }
            };
        }

        filterChain.doFilter(requestToUse, response);
    }

}
