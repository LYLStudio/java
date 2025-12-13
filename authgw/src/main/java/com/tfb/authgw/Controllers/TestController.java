package com.tfb.authgw.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;
import org.springframework.web.bind.annotation.RequestParam;

import com.tfb.authgw.Services.SessionService;

import jakarta.servlet.http.HttpSession;

@Controller
public class TestController {

    @Autowired
    private SessionService sessionService;

    @GetMapping("/")
    public String index(Model model, HttpSession session) throws QrGenerationException {
        String secret = sessionService.getSecret(session);
        if (secret == null) {
            SecretGenerator secretGenerator = new DefaultSecretGenerator();
            secret = secretGenerator.generate();
        }

        QrData data = new QrData.Builder()
                .label("example@example.com")
                .secret(secret)
                .issuer("ELK AUTHGW")
                .algorithm(HashingAlgorithm.SHA1) // More on this below
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = generator.generate(data);
        String mimeType = generator.getImageMimeType();
        String dataUri = getDataUriForImage(imageData, mimeType);

        sessionService.setSecret(session, secret);
        model.addAttribute("dataUri", dataUri);
        return "index";
    }

    @PostMapping("/verify")
    public String verifyOTP(@RequestParam String otp, HttpSession session, Model model) {
        String secret = sessionService.getSecret(session);
        if (secret == null) {
            model.addAttribute("message", "No secret found. Please refresh the page.");
            return "index";
        }

        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        boolean successful = verifier.isValidCode(secret, otp);

        model.addAttribute("message", successful ? "Valid OTP" : "Invalid OTP");
        return "index";
    }

}
