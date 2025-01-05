// javac *.java
// java ichecker createCert -k files\privatekey.enc -c files\publickey.cer
// java ichecker createReg -r files\registerfile.txt -p files\monitored -l files\logfile.txt -h SHA-256 -k files\privatekey.enc
// java ichecker check -r files\registerfile.txt -p files\monitored -l files\logfile.txt -h SHA-256 -c files\publickey.cer

public class ichecker {

    public static void main(String[] args) {

        String command = args[0];

        try {
            switch (command) {
                case "createCert":
                    CreateCertificate.createCertificate(args);
                    break;
                case "createReg":
                    CreateRegisterFile.CreateRegister(args);
                    break;
                case "check":
                    IntegrityChecker.checkIntegrity(args);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

