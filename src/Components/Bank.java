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
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author Alvin
 */
public class Bank {

    public static void openbankserver() throws IOException {
        ServerSocket BankServer = null;
        Socket BankSocket = null;
        BankServer = new ServerSocket(1000);
        BankSocket = BankServer.accept();
        DataOutputStream os = new DataOutputStream(BankSocket.getOutputStream());
        DataInputStream is = new DataInputStream(BankSocket.getInputStream());
        System.out.println(is.readUTF());
        os.close();
        is.close();
        BankSocket.close();
        BankServer.close();
    }

    public static X509Certificate createcertificate(CertAndKeyGen kgen) {
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

    public static CertAndKeyGen generateKeypair() {
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
//Creating certificate and keypair. You can use keypair to get public and private key
        CertAndKeyGen keypair = generateKeypair();
        X509Certificate Bank_certificate = createcertificate(keypair);
        try {
            openbankserver();
        } catch (IOException e) {
            System.out.println(e);
        }

    }
}
