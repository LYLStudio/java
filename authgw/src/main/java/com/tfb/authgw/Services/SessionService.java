package com.tfb.authgw.Services;

import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpSession;

@Service
public class SessionService {

    public void setSecret(HttpSession session, String secret) {
        session.setAttribute("secret", secret);
    }

    public String getSecret(HttpSession session) {
        return (String) session.getAttribute("secret");
    }
}