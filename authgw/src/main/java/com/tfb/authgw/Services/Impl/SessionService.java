package com.tfb.authgw.Services.Impl;

import org.springframework.stereotype.Service;

import com.tfb.authgw.Services.Interfaces.ISessionService;

import jakarta.servlet.http.HttpSession;

@Service
public class SessionService<T> implements ISessionService<T> {
    @Override
    public void setAttribute(HttpSession session, String key, T value) {
        session.setAttribute(key, value);
    }

    @SuppressWarnings("unchecked")
    @Override
    public T getAttribute(HttpSession session, String key) {
        return (T) session.getAttribute(key);
    }
}