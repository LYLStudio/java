package com.tfb.authgw.Controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Controller
public class TestController {
    @GetMapping("/")
    public String index(Model model) throws QrGenerationException {

        SecretGenerator secretGenerator = new DefaultSecretGenerator();
        String secret = secretGenerator.generate();

        QrData data = new QrData.Builder()
                .label("example@example.com")
                .secret(secret)
                .issuer("AppName")
                .algorithm(HashingAlgorithm.SHA1) // More on this below
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = generator.generate(data);
        String mimeType = generator.getImageMimeType();
        String dataUri = getDataUriForImage(imageData, mimeType);

        model.addAttribute("dataUri", dataUri);
        return "index";
    }
}
