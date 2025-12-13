package com.tfb.authgw.Services;

import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpSession;

@Service
public class SessionService {

    public void setAttribute(HttpSession session, String key, String value) {
        session.setAttribute(key, value);
    }

    public String getAttribute(HttpSession session, String key) {
        return (String) session.getAttribute(key);
    }
}