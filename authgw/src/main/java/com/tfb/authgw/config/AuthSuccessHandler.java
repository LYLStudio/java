package com.tfb.authgw.config;

import com.tfb.authgw.Services.OTPService;
import com.tfb.authgw.Services.SecretPersistenceService;
import com.tfb.authgw.Services.SessionService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private SecretPersistenceService secretPersistenceService;

    @Autowired
    private OTPService otpService;

    @Autowired
    private SessionService sessionService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        String userId = authentication.getName();
        String secret = secretPersistenceService.getSecret(userId);
        if (secret == null) {
            secret = otpService.generateSecret();
            secretPersistenceService.saveSecret(userId, secret);
        }
        sessionService.setAttribute(request.getSession(), "secret", secret);
        response.sendRedirect("/");
    }
}