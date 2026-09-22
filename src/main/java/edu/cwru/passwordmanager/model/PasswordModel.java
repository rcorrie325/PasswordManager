package edu.cwru.passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;


public class PasswordModel {

    private static final int ITERATIONS = 600_000;
    private static final int KEY_LENGTH = 256;

    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    // !!! DO NOT CHANGE - VERY IMPORTANT FOR GRADING !!!
    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    // TODO: You can set this to whatever you like to verify that the password the user entered is correct
    private static String verifyString = "Peanuts";

    private void loadPasswords() {
        // TODO: Replace with loading passwords from file, you will want to add them to the passwords list defined above
        // TODO: Tips: Use buffered reader, make sure you split on separator, make sure you decrypt password
        try (BufferedReader read = new BufferedReader(new FileReader (passwordFile))) {
            read.readLine();
            String text;
            while ((text = read.readLine()) != null) {
                if (text.isEmpty()) {
                    continue;
                }
                String[] words = text.split(separator, 2);
                String label = words[0];
                String password = words.length > 1 ? decrypt(words[1]) : "";

                passwords.add(new Password(label, password));
            }
        }
        catch (Exception e) {
            throw new RuntimeException(e);
            }
    }

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    static public void initializePasswordFile(String password) throws IOException {
        passwordFile.createNewFile();

        try {
            passwordFilePassword = password;
            passwordFileSalt = createSalt();

            passwordFileKey = generateKey(password, passwordFileSalt);

            //encrypt known word "Peanuts"
            String encryptedVerifyString = encrypt(verifyString);


            String encodedSalt = Base64.getEncoder().encodeToString(passwordFileSalt);

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(passwordFile))) {

                writer.write(encodedSalt + separator + encryptedVerifyString);

                writer.newLine();
            }

        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    static public boolean verifyPassword(String password) {
        passwordFilePassword = password; // DO NOT CHANGE

        try (BufferedReader read = new BufferedReader(new FileReader(passwordFile))) {

            String firstLine = read.readLine();

            if (firstLine == null) {
                return false;
            }

            String[] parts = firstLine.split(separator, 2);

            if (parts.length < 2) {
                return false;
            }


            passwordFileSalt = Base64.getDecoder().decode(parts[0]);

            passwordFileKey = generateKey(password, passwordFileSalt);

            String decryptedVerifyString = decrypt(parts[1]);

            //try peanuts, is true if AES key is correct
            return decryptedVerifyString.equals(verifyString);

        } catch (Exception e) {
            return false;
        }
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        passwords.remove(index);
        savePasswords();
    }

    //helper method persists the current GUI state to match memory
    private void savePasswords() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(passwordFile))) {

            // Rewrite the first line
            String encodedSalt = Base64.getEncoder().encodeToString(passwordFileSalt);

            String encryptedVerifyString = encrypt(verifyString);

            writer.write(encodedSalt + separator + encryptedVerifyString);

            writer.newLine();

            // Rewrite all saved passwords
            for (Password password : passwords) {

                String encryptedPassword = encrypt(password.getPassword());

                writer.write(password.getLabel() + separator + encryptedPassword);

                writer.newLine();
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void updatePassword(Password password, int index) {
        passwords.set(index, password);
        savePasswords();
    }




    public void addPassword(Password password) {
        passwords.add(password);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(passwordFile, true))) {

            String encryptedPassword = encrypt(password.getPassword());

            writer.write(password.getLabel() + separator + encryptedPassword);

            writer.newLine();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // TODO: Tip: Break down each piece into individual methods, for example: generateSalt(), encryptPassword, generateKey(), saveFile, etc ...
    // TODO: Use these functions above, and it will make it easier! Once you know encryption, decryption, etc works, you just need to tie them in
    private static byte[] createSalt(){
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    private static byte[] generateKey(String password, byte[] salt) throws Exception {

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        return factory.generateSecret(spec).getEncoded();
    }


    private static String encrypt(String userText) throws Exception{
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(passwordFileKey, "AES"));
        byte[] encrypted = cipher.doFinal(userText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    private static String decrypt(String encryptedText) throws Exception{
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(passwordFileKey, "AES"));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
