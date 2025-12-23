package com.tfb.authgw.Services.Impl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.tfb.authgw.Services.Interfaces.IOTPService;

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

@Service
public class OTPService implements IOTPService {
    @Value("${totp.code.length:6}")
    private int totpCodeLength;
    @Value("${totp.code.period:30}")
    private int totpCodePeriod;
    @Value("${totp.hash.algorithm:SHA1}")
    private String totpHashAlgorithm;

    private HashingAlgorithm getAlgorithm() {
        return HashingAlgorithm.valueOf(totpHashAlgorithm);
    }

    @Override
    public String generateSecret() {
        SecretGenerator secretGenerator = new DefaultSecretGenerator();
        return secretGenerator.generate();
    }

    @Override
    public String generateQrDataUri(String secret, String label, String issuer) throws QrGenerationException {
        QrData data = new QrData.Builder()
                .label(label)
                .secret(secret)
                .issuer(issuer)
                .algorithm(getAlgorithm())
                .digits(totpCodeLength)
                .period(totpCodePeriod)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = generator.generate(data);
        String mimeType = generator.getImageMimeType();
        return getDataUriForImage(imageData, mimeType);
    }

    @Override
    public boolean verifyOTP(String secret, String otp) {
        //System.out.println("Verifying OTP: " + otp + " with secret: " + secret);

        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(getAlgorithm(), totpCodeLength);
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        return verifier.isValidCode(secret, otp);
    }
}