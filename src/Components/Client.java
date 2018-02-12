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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author Alvin
 */
public class Client {

    Socket merchant = null;
    DataOutputStream os;
    DataInputStream is;
    String Username = null;
    int accountnumber;
    Order order;
    Payment creditcardinfo = new Payment("5354545421222","Alvin", "Chacko", "20 Jane street");
    

    public void connecttomerchant() throws IOException {
        merchant = new Socket("127.0.0.1", 9999);
        os = new DataOutputStream(merchant.getOutputStream());
        is = new DataInputStream(merchant.getInputStream());
    }

    public void sendtomerchant() {

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
            System.out.println("Certificate : " + certificate.toString());
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
        CertAndKeyGen keypair = Alvin.generateKeypair();
        X509Certificate Client_certificate = Alvin.createcertificate(keypair);
        RequestMessage init = new RequestMessage();
        init.getInitStringMessage().add("Initialization");
        System.out.println(init.toString());
        try {
            Alvin.connecttomerchant();
        } catch (IOException e) {
            System.out.println(e);
        }

    }
}
