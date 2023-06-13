package com.nhnent.edu.security;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

// TODO #6: 로그인 실패 핸들러
public class CustomLoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception)
        throws IOException, ServletException {
        HttpSession session = request.getSession();

        boolean isInvalidUsername = (exception instanceof UsernameNotFoundException);
        boolean isInvalidPassword = (exception instanceof BadCredentialsException);

        session.setAttribute("invalidUsername", isInvalidUsername);
        session.setAttribute("invalidPassword", isInvalidPassword);

        response.sendRedirect("/login/form?error");
    }
}
