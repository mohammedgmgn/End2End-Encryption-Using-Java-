package com.company;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class Main {
/**
 *
 * Text message security model
 * Step 1: The sender type Text Message (TM)
 * Step 2: TM converted to Bytes Array (BA)
 * Step 3: Encrypt the BA (EBA): performed by AES with the generated ECDH secure key (Shared Key)
 * Step 4: Convert the EBA to String (ES)
 * Step 5: Send the ES to the server
 * Step 6: The recipient receive the ES
 * Step 7: Convert the received ES to Bytes Array (EBA)
 * Step 8: Decrypt the EBA (BA)
 * Step 9: Convert the BA to string which is same the sender
 * message (TM)
 *
 * */
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String originalString = "My Plain Text";

        System.out.println("Original String to encrypt - " + originalString);
        // generate KyPair for each User
        KeyPair keyPairA = generateECKeys();
        KeyPair keyPairB = generateECKeys();

         // generate Shared Key using  private and public of the other
        SecretKey sharedKeyB = generateSharedSecret(keyPairB.getPrivate(),keyPairA.getPublic());

        //Encrypt message Using Shared Key
        byte[] encryptedString = encryptAes(originalString,getSharedKey(sharedKeyB.getFormat()));
        System.out.println("Encrypted String - " + encryptedString);
        SecretKey sharedKeyA = generateSharedSecret(keyPairA.getPrivate(),
                keyPairB.getPublic());
        String decryptedString = decryptAes(encryptedString,getSharedKey(sharedKeyA.getFormat()));
        System.out.println("After decryption - " + decryptedString);


    }

    private static String getSharedKey(String format) {
        return format+"asdfasfffsg5g";
    }

    private static KeyPair generateECKeys() {
        try {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    "ECDH", "BC");
            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static SecretKey generateSharedSecret(PrivateKey privateKey,
                                                 PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            SecretKey key = keyAgreement.generateSecret("AES");

            System.out.println("Bytes - " +key.getFormat().getBytes().toString());

            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException
                | NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] encryptAes(String value,String sharedKey) {

        try {


            SecretKeySpec skeySpec = new SecretKeySpec(sharedKey.getBytes("UTF-8"), "AES");


            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);



            byte[] encrypted = cipher.doFinal(value.getBytes());

             return encrypted;


        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return null;

    }

    private static String decryptAes(byte[] encMsg,String SharedKey) {

        try {


            SecretKeySpec skeySpec = new SecretKeySpec(SharedKey.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.DECRYPT_MODE, skeySpec);

            byte[] original = cipher.doFinal(encMsg);

            return new String(original);
        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return null;
    }



}


