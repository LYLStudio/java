package com.tfb.authgw.Services.Impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
public class SecretPersistenceService {

    private static final String SECRETS_FILE = "totp-secrets.json";
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String getSecret(String userId) {
        Map<String, String> secrets = loadSecrets();
        return secrets.get(userId);
    }

    public void saveSecret(String userId, String secret) {
        Map<String, String> secrets = loadSecrets();
        secrets.put(userId, secret);
        saveSecrets(secrets);
    }

    private Map<String, String> loadSecrets() {
        try {
            File file = new File(SECRETS_FILE);
            if (!file.exists()) {
                return new HashMap<>();
            }
            return objectMapper.readValue(file, new TypeReference<Map<String, String>>() {
            });
        } catch (IOException e) {
            e.printStackTrace();
            return new HashMap<>();
        }
    }

    private void saveSecrets(Map<String, String> secrets) {
        try {
            objectMapper.writeValue(new File(SECRETS_FILE), secrets);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}