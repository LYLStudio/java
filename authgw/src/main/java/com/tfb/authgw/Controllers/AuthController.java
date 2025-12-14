package com.tfb.authgw.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import org.springframework.web.bind.annotation.RequestParam;

import com.tfb.authgw.Services.OTPService;
import com.tfb.authgw.Services.SessionService;

import jakarta.servlet.http.HttpSession;

@Controller
public class AuthController {

    @Autowired
    private SessionService sessionService;

    @Autowired
    private OTPService otpService;

    @PostMapping("/verify")
    public String verifyOTP(@RequestParam String otp, HttpSession session, Model model) {
        String secret = sessionService.getAttribute(session, "secret");
        if (secret == null) {
            model.addAttribute("message", "No secret found. Please refresh the page.");
            return "index";
        }

        boolean successful = otpService.verifyOTP(secret, otp);

        model.addAttribute("message", successful ? "Valid OTP" : "Invalid OTP");
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
