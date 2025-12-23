package com.tfb.authgw.Services.Interfaces;

import jakarta.servlet.http.HttpSession;

public interface ISessionService<T> {

    void setAttribute(HttpSession session, String key, T value);

    T getAttribute(HttpSession session, String key);
    
}