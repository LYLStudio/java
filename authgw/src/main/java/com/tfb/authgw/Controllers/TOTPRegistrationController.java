package com.tfb.authgw.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.tfb.authgw.Services.OTPService;
import com.tfb.authgw.Services.SessionService;

import dev.samstevens.totp.exceptions.QrGenerationException;
import jakarta.servlet.http.HttpSession;

/* 僅內部網路可以連線確保來源對象及身份識別，
外部連線僅能驗證OTP本身，不允許產生驗證氣註冊資訊 */
@Controller
@RequestMapping("/totp")
public class TOTPRegistrationController {

    @Autowired
    private OTPService otpService;

    @Autowired
    private SessionService sessionService;

    @Value("${totp.issuer}")
    private String totpIssuer;

    @GetMapping("/register")
    public String register(Model model, HttpSession session) throws QrGenerationException {
        // 產生新的 secret
        String secret = sessionService.getAttribute(session, "secret");
        String userId = sessionService.getAttribute(session, "userId");
        // 產生 QRCode Data URI
        String dataUri = otpService.generateQrDataUri(secret, userId + "@fubon.com", totpIssuer);
        model.addAttribute("dataUri", dataUri);

        return "totp-register"; // 顯示 QRCode 的頁面
    }
}