import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.*;

public class IntegrityChecker {

    public static void checkIntegrity(String[] args) throws Exception {
        String registryFilePath = null, directoryPath = null, logFilePath = null, hashAlgorithm = null, certPath = null;

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
                case "-c": certPath = args[++i]; break;
                default:
                    System.out.println("Unknown argument: " + args[i]);
                    return;
            }
        }

        // Validate inputs
        if (registryFilePath == null || directoryPath == null || logFilePath == null || hashAlgorithm == null || certPath == null) {
            System.out.println("Usage: check -r <RegFile> -p <Path> -l <LogFile> -h <Hash> -c <PubKeyCertificate>");
            return;
        }

        // Step 1: Verify the digital signature
        boolean isVerified = verifySignature(registryFilePath, certPath);
        if (!isVerified) {
            log(logFilePath, "Registry file verification failed!");
            System.out.println("Registry file verification failed!");
            return;
        }

        System.out.println("Registry file verified successfully.");

        // Step 2: Check directory integrity
        checkDirectoryIntegrity(registryFilePath, directoryPath, logFilePath, hashAlgorithm);
        System.out.println("Integrity check completed.");
    }


    // Method to verify the digital signature at the end of the registry file
    private static boolean verifySignature(String registryFilePath, String certPath) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(registryFilePath));

        // Extract the signature from the last line
        String signatureLine = lines.get(lines.size() - 1).trim();

        if (!signatureLine.startsWith("#signature#")) {
            return false;
        }
        String signatureBase64 = signatureLine.replace("#signature# ", "").trim();

        // Remove the signature line for verification
        lines.remove(lines.size() - 1);

        // Join the remaining lines into a single string with consistent newlines
        StringBuilder contentBuilder = new StringBuilder();
        for (String line : lines) {
            contentBuilder.append(line.trim()).append("\n"); // Ensure consistent newlines
        }
        for (int i = 0; i < lines.size(); i++) {
            if (i != lines.size()-1) contentBuilder.append(lines.get(i).trim()).append("\n");
            else contentBuilder.append(lines.get(i).trim());
        }

        byte[] contentBytes = contentBuilder.toString().getBytes("UTF-8"); // Use UTF-8 for consistency

        // Load the public key from the certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream certStream = Files.newInputStream(Paths.get(certPath))) {
            Certificate certificate = certFactory.generateCertificate(certStream);
            PublicKey publicKey = certificate.getPublicKey();


            // Verify the signature using the public key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(contentBytes);

            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            System.out.println("Error verifying signature: " + e.getMessage());
            return false;
        }
    }

    // Method to check directory integrity
    private static void checkDirectoryIntegrity(String registryFilePath, String directoryPath, String logFilePath, String hashAlgorithm) throws Exception {
        Map<String, String> registryMap = loadRegistry(registryFilePath);
        Set<String> currentFiles = new HashSet<>();

        // Check each file in the directory
        Files.walkFileTree(Paths.get(directoryPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                try {
                    String currentHash = hashFile(file, hashAlgorithm);
                    String filePath = file.toString();

                    currentFiles.add(filePath);

                    if (registryMap.containsKey(filePath)) {
                        if (!registryMap.get(filePath).equals(currentHash)) {
                            log(logFilePath, filePath + " is altered");
                        }
                        registryMap.remove(filePath);
                    } else {
                        log(logFilePath, filePath + " is created");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return FileVisitResult.CONTINUE;
            }
        });

        // Check for deleted files
        for (String missingFile : registryMap.keySet()) {
            log(logFilePath, missingFile + " is deleted");
        }

        // Log if no changes were detected
        if (registryMap.isEmpty() && currentFiles.size() == registryMap.size()) {
            log(logFilePath, "The directory is checked and no change is detected!");
        }
    }

    // Load registry into a map
    private static Map<String, String> loadRegistry(String registryFilePath) throws IOException {
        Map<String, String> registryMap = new HashMap<>();
        List<String> lines = Files.readAllLines(Paths.get(registryFilePath));

        for (String line : lines) {
            if (line.startsWith("#signature#")) break;
            String[] parts = line.split(" ");
            registryMap.put(parts[0], parts[1]);
        }
        return registryMap;
    }



    // Method to log messages with a timestamp
    private static void log(String logFilePath, String message) {
        try (PrintWriter logWriter = new PrintWriter(new FileWriter(logFilePath, true))) {
            String timestamp = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date());
            logWriter.println("[" + timestamp + "]: " + message);
        } catch (IOException e) {
            e.printStackTrace();
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


}
