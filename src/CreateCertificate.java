import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Scanner;

public class CreateCertificate {
    private static final String RSA_KEY_SIZE = "2048";
    public static void createCertificate(String[] args) throws Exception {
        String privateKeyPath = null, publicKeyCertPath = null;

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "-k": privateKeyPath = args[++i]; break;
                case "-c": publicKeyCertPath = args[++i]; break;
                default: break;
            }
        }
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password for private key encryption: ");
        String password = scanner.nextLine();

        // 1. Adım: keytool kullanarak anahtar çifti ve sertifika oluştur
        String keystore = "ichecker.jks";
        String alias = "ichecker";
        String storepass = "password1";
        String keypass = "password1";

        ProcessBuilder processBuilder = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", alias,
                "-keyalg", "RSA",
                "-keysize", RSA_KEY_SIZE,
                "-validity", "365",
                "-keystore", keystore,
                "-storepass", storepass,
                "-keypass", keypass,
                "-dname", "CN=ARK4UTH, OU=Security, O=MyApp, L=Ankara, ST=TR, C=TR"
        );

        processBuilder.inheritIO();
        Process process = processBuilder.start();
        process.waitFor();

        // 2. Adım: Sertifikayı çıkart
        ProcessBuilder exportBuilder = new ProcessBuilder(
                "keytool", "-exportcert",
                "-alias", alias,
                "-file", publicKeyCertPath,
                "-keystore", keystore,
                "-storepass", storepass
        );

        exportBuilder.inheritIO();
        Process exportProcess = exportBuilder.start();
        exportProcess.waitFor();

        // 3. Adım: Özel anahtarı AES ile şifrele ve kaydet
        encryptPrivateKey(keystore, alias, privateKeyPath, password, storepass, keypass);

        System.out.println("Certificate and encrypted private key created successfully!");
    }

    public static void encryptPrivateKey(String keystore, String alias, String privateKeyPath,
                                         String password, String storepass, String keypass) throws Exception {
        // Load the keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystore)) {
            ks.load(fis, storepass.toCharArray());
        }

        // Retrieve the private key
        Key key = ks.getKey(alias, keypass.toCharArray());
        if (key == null) {
            throw new Exception("Private key not found in keystore");
        }

        // Hash the user-provided password to generate the AES key
        byte[] aesKey = MessageDigest.getInstance("MD5").digest(password.getBytes("UTF-8"));
        SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
        // Encrypt the private key using AES
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedKey = cipher.doFinal(key.getEncoded());

        // Save the encrypted private key to file
        try (FileOutputStream fos = new FileOutputStream(privateKeyPath)) {
            fos.write(encryptedKey);
        }
        System.out.println("Private key encrypted successfully!");
    }

}
