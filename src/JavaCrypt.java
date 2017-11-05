/*
 * @JavaCrypt.java
 * Java PBE implementation
 * With known plain text Brute force attack
 *
 *
 *
 * Assignment01_Comp522
 * University of Liverpool
 *
 *
 * @author J.Wharton
 * 2017
 */
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.DestroyFailedException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Scanner;


public class JavaCrypt {

    private static String secretAlgorithm = "PBEWithMD5AndDes";

    public static String getUserInputPassword(Scanner userInput)
    {

        // Read in password. Restrict password space.
        System.out.printf("\n%s\n%s",
                "Pass may contain numerical characters only. \"{0-9}\"",
                "Enter a pass phrase :");

        while (!userInput.hasNext("[0-9]*$"))           // regix restrict input to 0-9
        {
            System.out.println("Invalid password: ");
            userInput.next();
        }
        String password = userInput.next();
        System.out.println("Input Received: " + (password));   // notify user of recorded input.
        return password;
    }


    public static void main(String[] args) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException, DestroyFailedException
    {

        // present user instructions - Menu
        System.out.printf("\n%s\n%s\n%s\n%s\n%s\n",
                "******************************", "******Welcome_to_JavaCrypt******",
                "******************************", "This program will encrypt & decrypt a predefined message using PBE",
                "Brute force attack will follow");

        // Generate password based encryption parameters
        System.out.println("\nGenerating salt");

        // *******************PBE_Parameters***********************
        // SecureRandom Random = new SecureRandom(); - conventionally used
        byte[] salt = {
                (byte) 0x4f,
                (byte) 0x73,
                (byte) 0x7f,
                (byte) 0x8c,
                (byte) 0x7e,
                (byte) 0xe5,
                (byte) 0xee,
                (byte) 0x99};   //Random.nextBytes(salt); conventionally used.

        // Set iteration count. Normal range between - 1000-4000+
        int iterationCount = 1024;

        System.out.println("\n===============PBE_PARAMETERS_SET================");
        System.out.println("Iteration count :" + (iterationCount));
        System.out.println("salt values are :" + Arrays.toString(salt));
        System.out.println("\nUSING : " + secretAlgorithm);




        //***********************Request_Password**************************************
        Scanner userInput = new Scanner(System.in);
        String encryptWithPassword = getUserInputPassword(userInput);
        int passwordLength = encryptWithPassword.length();

        //****************************ENCRYPTION***************************************
        System.out.println("\n===============ENCRYPTING===============");
        String messageToEncrypt = "I want to hide the contents of this message";
        byte[] cipherText = getCipherText(messageToEncrypt, encryptWithPassword, salt, iterationCount);
        System.out.println("Message successfully encrypted! ");
        System.out.println("The enciphered plaintext is : " + Utils.toHex(cipherText));
        System.out.println("test " + Utils.toHex(cipherText, 5));
        System.out.println("\nProceeding to decryption");

        //***************************Verify_password******************************
        String decryptPassword = askForPassword(userInput, encryptWithPassword);

        //***************************DECRYPTION****************************************
        getPlainText(cipherText, decryptPassword, salt,iterationCount);

        //*******************************BRUTE_FORCE***********************************
        System.out.println("\n===============MOVING_TO_BRUTE_FORCE===============");

        DateTimeFormatter formatOfDate = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
        System.out.println("Brute force started: " + formatOfDate.format(LocalDateTime.now()));
        System.out.println("Please standby.");
        runBruteForceSuite(passwordLength, salt, iterationCount, cipherText );
    }

    private static Boolean runBruteForceSuite(int passwordLength, byte[] salt, int iterationCount, byte[] cipherText)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {

        if (doBruteForce(passwordLength, salt, iterationCount, cipherText)) {
            System.out.println(passwordLength + " char Brute force succeeded!");
            return true;
        } else {
            System.out.println(passwordLength + " char Brute force failed!");
        }

        return false;
    }

    private static Boolean doBruteForce(int passwordLength, byte[] salt, int iterationCount, byte [] existingCipherText)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        StringBuilder testPass = new StringBuilder();
        long startTime = System.currentTimeMillis();
        int abortAfter = 20000;
        int attemptCount = 0;

        while (true) {
            attemptCount += 1;
//            if (attemptCount >= abortAfter) throw new RuntimeException("Abort count reached."); //DEBUGGING

            testPass = BruteForce.generateStringFromInput(testPass, passwordLength, 48, 57);
            byte[] cipherText = getCipherText("I want to hide the contents of this message", testPass.toString(), salt, iterationCount);

            DateTimeFormatter formatOfDate = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");

            if (Arrays.equals(cipherText, existingCipherText)) {
                System.out.println("\nCipher hex match. Found password! :" + testPass.toString());
                System.out.println("Brute force ended: " + formatOfDate.format(LocalDateTime.now()));

                String decodedString = getPlainText(existingCipherText, testPass.toString(), salt, iterationCount);

//                System.out.println("\nDecrypting with password permutation :" + decodedString);
                System.out.println("\n===================Brute_Force_Report====================\n");
                System.out.println("It took :" + convertMilliseconds(System.currentTimeMillis() - startTime));
                System.out.println("Tried " + attemptCount + " password permutations");
                return true;
            }
        }
    }

    private static String askForPassword(Scanner storedPassword, String encryptionKey) {
        System.out.printf("\n%s\n%s",
                "===============DECRYPTING===============",
                "To decipher message, re-enter password");

        String decryptionPassword = getUserInputPassword(storedPassword);

        while (!decryptionPassword.equals(encryptionKey)) {
            System.out.printf("%s\n",
                    "Passwords do not match, try again...");
            decryptionPassword = getUserInputPassword(storedPassword);

        }

        System.out.println("Password match! ");

        storedPassword.close();

        return encryptionKey;
    }


    private static byte[] getEncryptedMessage(PBEParameterSpec pbeParameterSpec, SecretKey pbeKey, Cipher pbeCipher, String message)
            throws InvalidKeyException,
            InvalidAlgorithmParameterException,
            IllegalBlockSizeException,
            BadPaddingException
    {
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParameterSpec);
        byte[] clearText = message.getBytes();
        byte[] cipherText = pbeCipher.doFinal(clearText);
        return cipherText;
    }

    public static String decryptMessage(
            PBEParameterSpec pbeParameterSpec, SecretKey pbeKey, Cipher pbeCipher, byte[] cipherText)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParameterSpec);
        String plainText = new String(pbeCipher.doFinal(cipherText));

        System.out.println("\nDecrypting message....");
        System.out.println("The plaintext is : " + (plainText));

        return plainText;
    }



    private static byte[] getCipherText (String message, String encryptWithPassword, byte [] salt, int iterationCount)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

        PBEKeySpec pbeKeySpec = new PBEKeySpec(encryptWithPassword.toCharArray());

        // implies CBC as mode. and PKCS5Padding scheme only.
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(secretAlgorithm);


        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        pbeKeySpec = new PBEKeySpec(encryptWithPassword.toCharArray());
        Cipher pbeCipher = Cipher.getInstance(secretAlgorithm);

        return getEncryptedMessage(pbeParameterSpec, pbeKey, pbeCipher, message);
    }


    public static String getPlainText(byte[] cipherText, String decryptWithPassword, byte [] salt, int iterationCount)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {

        Cipher pbeCipher = Cipher.getInstance("PBEWithMd5AndDES");
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMd5AndDES");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(decryptWithPassword.toCharArray());

        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        return decryptMessage(new PBEParameterSpec(salt, iterationCount), pbeKey, pbeCipher, cipherText);
    }

    private static String convertMilliseconds(long input) {
        int days = 0, hours = 0, minutes = 0, seconds = 0, millis = 0;

        int day = 86400000;
        int hour = 3600000;
        int minute = 60000;
        int second = 1000;

        if (input >= day) {
            days = (int) (input / day);
            millis = (int) (input % day);
        } else
            millis = (int) input;

        if (millis >= hour) {
            hours = millis / hour;
            millis = millis % hour;
        }

        if (millis >= minute) {
            minutes = millis / minute;
            millis = millis % minute;
        }

        if (millis >= second) {
            seconds = millis / second;
            millis = millis % second;
        }
        return (days + " day(s), " + hours + "h, " + minutes + " min, " + seconds + "s and " + millis + "ms");
    }
}



