#!/bin/bash
# 建立 Spring Boot AuthGW 專案骨架
# JDK 25 + Spring Boot 3.5.x + Maven

PROJECT_ROOT="authgw"

echo "建立專案目錄結構..."

mkdir -p $PROJECT_ROOT/src/main/java/com/example/authgw/config
mkdir -p $PROJECT_ROOT/src/main/java/com/example/authgw/controller
mkdir -p $PROJECT_ROOT/src/main/java/com/example/authgw/service
mkdir -p $PROJECT_ROOT/src/main/java/com/example/authgw/util
mkdir -p $PROJECT_ROOT/src/main/resources/static
mkdir -p $PROJECT_ROOT/src/test/java/com/example/authgw

# 建立 pom.xml
cat > $PROJECT_ROOT/pom.xml << 'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>authgw</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>authgw</name>
    <description>Auth Gateway with LDAP + OTP for Kibana</description>

    <properties>
        <java.version>25</java.version>
        <spring.boot.version>3.5.0</spring.boot.version>
        <maven.compiler.source>${java.version}</maven.compiler.source>
        <maven.compiler.target>${java.version}</maven.compiler.target>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>${spring.boot.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.ldap</groupId>
            <artifactId>spring-ldap-core</artifactId>
        </dependency>
        <dependency>
            <groupId>com.warrenstrange</groupId>
            <artifactId>googleauth</artifactId>
            <version>1.6.0</version>
        </dependency>
        <dependency>
            <groupId>com.google.zxing</groupId>
            <artifactId>core</artifactId>
            <version>3.5.3</version>
        </dependency>
        <dependency>
            <groupId>com.google.zxing</groupId>
            <artifactId>javase</artifactId>
            <version>3.5.3</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <configuration>
                    <release>${java.version}</release>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
EOF

# 建立 Application 主程式
cat > $PROJECT_ROOT/src/main/java/com/example/authgw/AuthgwApplication.java << 'EOF'
package com.example.authgw;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthgwApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthgwApplication.class, args);
    }
}
EOF

# 建立 Controller 範例
cat > $PROJECT_ROOT/src/main/java/com/example/authgw/controller/AuthController.java << 'EOF'
package com.example.authgw.controller;

import com.example.authgw.service.LdapService;
import com.example.authgw.service.OtpService;
import com.example.authgw.service.SessionService;
import com.example.authgw.util.QrCodeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired private LdapService ldapService;
    @Autowired private OtpService otpService;
    @Autowired private SessionService sessionService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        if (!ldapService.authenticate(username, password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("AD驗證失敗");
        }
        String secret = otpService.getOrCreateSecret(username);
        String otpAuthUrl = "otpauth://totp/AuthGW:" + username + "?secret=" + secret + "&issuer=AuthGW";
        try {
            byte[] qr = QrCodeUtil.generateQr(otpAuthUrl);
            return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(qr);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/otp")
    public ResponseEntity<?> otp(@RequestParam String username, @RequestParam int code) {
        if (!otpService.verifyOtp(username, code)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("OTP驗證失敗");
        }
        sessionService.createSession(username);
        return ResponseEntity.ok("驗證成功，導向Kibana");
    }
}
EOF

# 建立 Service 範例
cat > $PROJECT_ROOT/src/main/java/com/example/authgw/service/LdapService.java << 'EOF'
package com.example.authgw.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.stereotype.Service;

@Service
public class LdapService {
    @Autowired
    private LdapTemplate ldapTemplate;

    public boolean authenticate(String username, String password) {
        try {
            return ldapTemplate.authenticate(
                LdapQueryBuilder.query().where("sAMAccountName").is(username),
                password
            );
        } catch (Exception e) {
            return false;
        }
    }
}
EOF

cat > $PROJECT_ROOT/src/main/java/com/example/authgw/service/OtpService.java << 'EOF'
package com.example.authgw.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Service
public class OtpService {
    private final Map<String, String> secrets = new ConcurrentHashMap<>();
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public String getOrCreateSecret(String username) {
        return secrets.computeIfAbsent(username, u -> gAuth.createCredentials().getKey());
    }

    public boolean verifyOtp(String username, int code) {
        String secret = secrets.get(username);
        if (secret == null) return false;
        return gAuth.authorize(secret, code);
    }
}
EOF

cat > $PROJECT_ROOT/src/main/java/com/example/authgw/service/SessionService.java << 'EOF'
package com.example.authgw.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Service
public class SessionService {
    private final Map<String, Boolean> sessions = new ConcurrentHashMap<>();

    public void createSession(String username) {
        sessions.put(username, true);
    }

    public boolean hasSession(String username) {
        return sessions.getOrDefault(username, false);
    }
}
EOF

# 建立 QR 工具
cat > $PROJECT_ROOT/src/main/java/com/example/authgw/util/QrCodeUtil.java << 'EOF'
package com.example.authgw.util;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.client.j2se.MatrixToImageWriter;

import java.io.ByteArrayOutputStream;

public class QrCodeUtil {
    public static byte[] generateQr(String otpAuthUrl) throws Exception {
        BitMatrix matrix = new QRCodeWriter().encode(otpAuthUrl, BarcodeFormat.QR_CODE, 300, 300);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", baos);
        return baos.toByteArray();
    }
}
EOF

# 建立