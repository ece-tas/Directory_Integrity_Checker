import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

public class CreateRegisterFile {
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    public static void CreateRegister(String[] args) throws Exception {
        String registryFilePath = null, directoryPath = null, logFilePath = null, privateKeyPath = null, hashAlgorithm = null;

        // Parsing arguments
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "-r": registryFilePath = args[++i]; break;
                case "-p": directoryPath = args[++i]; break;
                case "-l": logFilePath = args[++i]; break;
                case "-h": hashAlgorithm = args[++i];
                    // Validate the hash algorithm
                    if (!"MD5".equalsIgnoreCase(hashAlgorithm) && !"SHA-256".equalsIgnoreCase(hashAlgorithm)) return;
                    break;
                case "-k": privateKeyPath = args[++i]; break;
                default: break;
            }
        }
        if (registryFilePath == null || directoryPath == null || logFilePath == null || hashAlgorithm == null || privateKeyPath == null) {
            System.out.println("Usage: createReg -r <RegFile> -p <Path> -l <LogFile> -h <Hash> -k <PriKey>");
            return;
        }
        // Ask user for password to decrypt the private key
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password for private key decryption: ");
        String password = scanner.nextLine();

        // Decrypt the private key
        PrivateKey privateKey = decryptPrivateKey(privateKeyPath, password);
        if (privateKey == null) {
            System.out.println("Failed to decrypt private key. Please check your password.");
            return;
        }

        List<String> registryEntries = new ArrayList<>();
        try (PrintWriter registryWriter = new PrintWriter(new FileWriter(registryFilePath));
             PrintWriter logWriter = new PrintWriter(new FileWriter(logFilePath, true))) {

            log(logWriter, "Registry file is created at " + registryFilePath + "!");

            // Walk through the directory and hash each file
            String finalHashAlgorithm = hashAlgorithm;
            Files.walkFileTree(Paths.get(directoryPath), new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    try {
                        String hash = hashFile(file, finalHashAlgorithm);
                        String entry = file.toString() + " " + hash;
                        registryEntries.add(entry);
                        registryWriter.println(entry);
                        log(logWriter, file.toString() + " is added to registry.");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return FileVisitResult.CONTINUE;
                }
            });

            // Generate a digital signature for the registry content (excluding the last line)
            String signature = signRegistryContent(registryEntries, privateKey);

            registryWriter.println("#signature# " + signature);


            log(logWriter, registryEntries.size() + " files are added to the registry and registry creation is finished!");
        }

        System.out.println("Registry created successfully!");


    }



    // Method to decrypt the private key using AES
    private static PrivateKey decryptPrivateKey(String privateKeyPath, String password) throws Exception {
        try {
            byte[] aesKey = MessageDigest.getInstance("MD5").digest(password.getBytes("UTF-8"));
            SecretKeySpec secretKey = new SecretKeySpec(aesKey, AES_ALGORITHM);

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedKey = Files.readAllBytes(Paths.get(privateKeyPath));
            byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);

            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedKeyBytes));

            // Step 4: Validate the decrypted key by checking its type
            if (privateKey != null && privateKey.getAlgorithm().equalsIgnoreCase("RSA")) {
                System.out.println("Private key successfully decrypted!");
                return privateKey;
            } else {
                return null;
            }
        } catch (Exception e) {
            // If decryption or validation fails, print an error and return null
            System.out.println("Error: Incorrect password or corrupted private key file.");
            return null;
        }
    }

    private static String hashFile(Path filePath, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        try (InputStream fis = Files.newInputStream(filePath)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    private static String signRegistryContent(List<String> registryEntries, PrivateKey privateKey) throws Exception {
        // Create a single string with all registry entries (excluding the signature line)
        StringBuilder registryContent = new StringBuilder();
        for (int i = 0; i < registryEntries.size(); i++) {
            if (i != registryEntries.size()-1) registryContent.append(registryEntries.get(i).trim()).append("\n");
            else registryContent.append(registryEntries.get(i).trim());
        }

        // Hash the entire registry content
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] contentHash = digest.digest(registryContent.toString().getBytes("UTF-8"));

        // Sign the hash
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(contentHash);

        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static void log(PrintWriter logWriter, String message) {
        String timestamp = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date());
        logWriter.println("[" + timestamp + "]: " + message);
    }

}
