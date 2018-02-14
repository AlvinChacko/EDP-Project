/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

import OrderInfo.Order;
import OrderInfo.Payment;
import java.io.*;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author Alvin
 */
public class Client {

    Socket merchant = null;
    ObjectOutputStream os;
    ObjectInputStream is;
    String Username = null;
    int accountnumber;
    CertAndKeyGen keypair = generateKeypair();
    X509Certificate Client_certificate = createcertificate(keypair);
    X509Certificate Merchant_certificate;
    X509Certificate Bank_certificate;
    Order order;
    Payment creditcardinfo = new Payment("5354545421222", "Alvin", "Chacko", "20 Jane street");
    byte[] orderdigest;
    byte[] paymentdigest;
    byte[] combinedMD;
    byte[] dualsignature;

    public void connecttomerchant() throws IOException {
        merchant = new Socket("127.0.0.1", 9999);
        os = new ObjectOutputStream(merchant.getOutputStream());
        is = new ObjectInputStream(merchant.getInputStream());
        initiatetomerchant();
    }

    public void initiatetomerchant() {
        try {
            RequestMessage init = new RequestMessage();
            init.clearvariables();
            init.getInitStringMessage().add("Initiate");
            os.writeObject(init);
            init = (RequestMessage) is.readObject();

            //Initialize the correct variable from the recieved message
            order = new Order(init.InitStringMessage.get(0));
            Merchant_certificate = init.certificates.get(0);
            Bank_certificate = init.certificates.get(1);

            System.out.println("Order created with transaction id: " + order.getTransaction_id());
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void purchaserequest() {
        dualsignature();
    }

    public void encryptpaymentinfo() throws InvalidKeyException {
        try {
            //generate sessionkey
            KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
            kgen.init(256);
            SecretKey sessionkey = kgen.generateKey();
            Cipher desCipher;
            desCipher = Cipher.getInstance("RSA");

            //encrypt using session key
            desCipher.init(Cipher.ENCRYPT_MODE, sessionkey);
            

            desCipher = Cipher.getInstance("RSA");
            desCipher.init(Cipher.WRAP_MODE, Bank_certificate.getPublicKey());
            byte[] wrappedsessionkey = desCipher.wrap(sessionkey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | IllegalBlockSizeException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void createOrderMD() {
        try {
            MessageDigest orderd = MessageDigest.getInstance("SHA-1");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(order);
            oos.close();
            orderd.update(baos.toByteArray());
            orderdigest = orderd.digest();
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void createPaymentMD() {
        try {
            MessageDigest paymentd = MessageDigest.getInstance("SHA-1");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(creditcardinfo);
            oos.close();
            paymentd.update(baos.toByteArray());
            paymentdigest = paymentd.digest();
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void dualsignature() {
        try {
            MessageDigest duals = MessageDigest.getInstance("SHA-1");
            createOrderMD(); // Create Order MD
            createPaymentMD(); // Create Payment MD
            duals.update(orderdigest); // Update the message dist to include OIMD and PIMD
            duals.update(paymentdigest);
            combinedMD = duals.digest(); // Create the digest of the combined
            // Creating a digital signature 
            Signature dsign = Signature.getInstance("SHA1withRSA");
            dsign.initSign(keypair.getPrivateKey());
            dsign.update(combinedMD);
            dualsignature = dsign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void closeconnection() throws IOException {
        os.close();
        is.close();
        merchant.close();
    }

    public X509Certificate createcertificate(CertAndKeyGen kgen) {
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
        CertAndKeyGen kpair = null;
        try {
            kpair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            kpair.generate(1024);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kpair;
    }

    public static void main(String args[]) throws IOException, ClassNotFoundException {
        Client Alvin = new Client();
        try {
            Alvin.connecttomerchant();
        } catch (IOException e) {
            System.out.println(e);
        }

    }
}
