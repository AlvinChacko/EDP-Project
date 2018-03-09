/**
 *
 * @author BHATT
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

import static Components.Merchant.bankcertificate;
import java.io.*;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author Bhatt
 */
public class Bank {

    CertAndKeyGen kpair = generateKeypair();
    X509Certificate Bank_certificate = createcertificate(kpair);
    ServerSocket BankServer = null;
    Socket merchantSocket = null;
    ObjectInputStream is;
    ObjectOutputStream os;
    X509Certificate Merchant_certificate;
    RequestMessage authorizationmessage = new RequestMessage();
    static RequestMessage authorizationResponseMessage = new RequestMessage();
    static RequestMessage paymentResponseMessage = new RequestMessage();

    public void openbankserver() throws IOException {
        BankServer = new ServerSocket(1000);
        merchantSocket = BankServer.accept();
        os = new ObjectOutputStream(merchantSocket.getOutputStream());
        is = new ObjectInputStream(merchantSocket.getInputStream());
        os.writeObject(Bank_certificate);

        //  os.close();
        //is.close();
        // BankSocket.close();
        // BankServer.close();
    }

    public void connectToMerchant() throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {

//        merchantSocket = new Socket("127.0.0.1", 9999);
//        os = new ObjectOutputStream(merchantSocket.getOutputStream());
//        is = new ObjectInputStream(merchantSocket.getInputStream());

        RequestMessage inMsg = new RequestMessage();
        inMsg.clearvariables();
        inMsg = (RequestMessage) is.readObject();
        if (inMsg.InitStringMessage.contains("Authorization Request")) {
            try {
                recieveAuthorizationRequest();
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
    }

    //Cipher1
    //Revices merchant certificate
    //decrypts merchant information using banks private key 
    //unwraps session key1, decrypts encryptes information
    //Cipher2
    //decrypts customer information using banks private key
    //unwraps session key2 by customer
    //decrypts2 encrypted information by encryots2 
    public void recieveAuthorizationRequest() throws InvalidKeyException, IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {

        Merchant_certificate = authorizationmessage.certificates.get(0);

        Cipher deCipher1;
        Cipher deCipher2;
        try {
            deCipher1 = Cipher.getInstance("RSA");
            deCipher1.init(Cipher.DECRYPT_MODE, kpair.getPrivateKey());
            byte[] wrappedsessionkey2 = new byte[256];

            is.read(wrappedsessionkey2);
            SecretKey sessionKey2 = (SecretKey) deCipher1.unwrap(wrappedsessionkey2, "AES", Cipher.SECRET_KEY);

            byte[] encrpyted = new byte[256];
            is.read(encrpyted);

            deCipher1.init(Cipher.DECRYPT_MODE, sessionKey2);
            byte[] decrypted = deCipher1.doFinal(encrpyted);             //recieves decryptes information from client

            deCipher2 = Cipher.getInstance("RSA");
            deCipher2.init(Cipher.DECRYPT_MODE, kpair.getPrivateKey());
            byte[] wrappedsessionkey1 = new byte[256];

            is.read(wrappedsessionkey1);
            SecretKey sessionKey1 = (SecretKey) deCipher1.unwrap(wrappedsessionkey1, "AES", Cipher.SECRET_KEY);

            byte[] encrpyted2 = new byte[256];
            is.read(encrpyted);

            deCipher1.init(Cipher.DECRYPT_MODE, sessionKey2);
            byte[] decrypted2 = deCipher1.doFinal(encrpyted2);          //recieves decryptes Payment Information from customer

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    //Sends string response "Valid" 
    //Wraps the reponse in with generated session key 
    //Encryptes session key using merchants publickey
    //Attaches request message to the  writeObject via Outstream object
    public void sendAuthorizationResponse() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
        authorizationResponseMessage.InitStringMessage.add("Valid");

        KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
        kgen.init(256);
        SecretKey sessionkey3 = kgen.generateKey();

        Cipher deCipher3;
        deCipher3 = Cipher.getInstance("RSA");

        //encrypt using session key
        deCipher3.init(Cipher.ENCRYPT_MODE, sessionkey3);
        byte[] encrpyted1 = deCipher3.update(authorizationResponseMessage.InitStringMessage.get(0).getBytes());

        deCipher3.init(Cipher.WRAP_MODE, Merchant_certificate.getPublicKey());
        byte[] wrappedsessionkey3 = deCipher3.wrap(sessionkey3);
        authorizationResponseMessage.encrypteddata.add(encrpyted1);
        authorizationResponseMessage.encrypteddata.add(wrappedsessionkey3);

        authorizationResponseMessage.certificates.add(bankcertificate);

        os.writeObject(authorizationResponseMessage);                                    //sends authorization response to merchant with String message Valid 
    }

    public void recievepayementCaptureRequest() throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {

        //byte[] auth_msg = authorizationmessage.encrypteddata.get(1);
        Cipher deCipher5;
        try {
            deCipher5 = Cipher.getInstance("RSA");
            deCipher5.init(Cipher.DECRYPT_MODE, kpair.getPrivateKey());
            byte[] wrappedsessionkey4 = new byte[256];

            is.read(wrappedsessionkey4);
            SecretKey sessionKey4 = (SecretKey) deCipher5.unwrap(wrappedsessionkey4, "AES", Cipher.SECRET_KEY);

            byte[] encrpyted3 = new byte[256];
            is.read(encrpyted3);

            deCipher5.init(Cipher.DECRYPT_MODE, sessionKey4);
            byte[] decrypted3 = deCipher5.doFinal(encrpyted3);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Bank.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
//    

    public void sendpaymentCaptureResponse() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
        paymentResponseMessage.InitStringMessage.add("Payment Response");

        KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
        kgen.init(256);
        SecretKey sessionkey5 = kgen.generateKey();

        Cipher deCipher6;
        deCipher6 = Cipher.getInstance("RSA");

        //encrypt using session key
        deCipher6.init(Cipher.ENCRYPT_MODE, sessionkey5);
        byte[] encrpyted4 = deCipher6.update(paymentResponseMessage.InitStringMessage.get(0).getBytes());

        deCipher6.init(Cipher.WRAP_MODE, Merchant_certificate.getPublicKey());
        byte[] wrappedsessionkey5 = deCipher6.wrap(sessionkey5);
        paymentResponseMessage.encrypteddata.add(encrpyted4);
        paymentResponseMessage.encrypteddata.add(wrappedsessionkey5);

        paymentResponseMessage.certificates.add(bankcertificate);

        os.writeObject(paymentResponseMessage);
    }

    public static X509Certificate createcertificate(CertAndKeyGen kgen) {
        X509Certificate certificate = null;
        try {
            //Generate self signed certificate
            certificate = kgen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);
            //System.out.println("Certificate : " + certificate.toString());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IOException | CertificateException | SignatureException ex) {
            ex.printStackTrace();
        }
        return certificate;
    }

    public CertAndKeyGen generateKeypair() {
        try {
            kpair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            kpair.generate(1024);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kpair;
    }

//    public void decryptingpaymentfromcustomer() throws IOException, ClassNotFoundException {;;;
//        RequestMessage purchasemessage = new RequestMessage();
//        //Recieve the object
//        purchasemessage = (RequestMessage) is.readObject();
//        SealedObject s_payment = purchasemessage.sealedobject.get(0);
//        try {
//            //Decrypt the session key using own private key
//            Cipher desCipher2 = Cipher.getInstance("RSA");
//            Key sessionkey;
//            desCipher2.init(Cipher.UNWRAP_MODE, kpair.getPrivateKey());
//            sessionkey = desCipher2.unwrap(purchasemessage.encrypteddata.get(1), "AES", Cipher.SECRET_KEY);
//
//            // Decrypting the payment object using the unwrapped session key
//            Cipher desCipher = Cipher.getInstance("AES");
//            desCipher.init(Cipher.DECRYPT_MODE, sessionkey);
//            p = (Payment) s_payment.getObject(desCipher);
//            System.out.println(p.getFname() + p.getLname() + p.getAddress() + p.getCredicardnumber());
//            checkCustomerAccountability();
//        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
//            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
//        }
//
//    }
    public static void main(String args[]) throws IOException, ClassNotFoundException {

        try {
            Bank a = new Bank();
            a.openbankserver();
        } catch (IOException e) {
            System.out.println(e);
        }
    }

}
