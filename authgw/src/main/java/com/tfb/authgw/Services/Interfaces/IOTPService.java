package com.tfb.authgw.Services.Interfaces;

public interface IOTPService {

    String generateSecret();

    String generateQrDataUri(String secret, String label, String issuer) throws Exception;

    boolean verifyOTP(String secret, String otp);
} 