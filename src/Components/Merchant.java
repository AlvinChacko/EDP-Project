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
public class Merchant {

    public static void openclientserver() throws IOException {
        ServerSocket MerchantServer = null;
        Socket clientSocket = null;
        MerchantServer = new ServerSocket(9999);
        clientSocket = MerchantServer.accept();
        DataOutputStream os = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream is = new DataInputStream(clientSocket.getInputStream());
        os.writeUTF("Connected to Client");
        System.out.println("Conected");
        os.close();
        is.close();
        clientSocket.close();
        MerchantServer.close();
    }

    public static void connecttobank() throws IOException {
        Socket Bank = null;
        Bank = new Socket("127.0.0.1", 1000);
        DataInputStream is2 = new DataInputStream(Bank.getInputStream());
        DataOutputStream os2 = new DataOutputStream(Bank.getOutputStream());
        os2.writeUTF("Connected to Bank");
        os2.close();
        is2.close();
        Bank.close();
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

    public static void main(String args[]) throws ClassNotFoundException, InterruptedException {
        //Creating certificate and keypair. You can use keypair to get public and private key
        CertAndKeyGen keypair = generateKeypair();
        X509Certificate Merchant_certificate = createcertificate(keypair);

        try {
            openclientserver();
            connecttobank();
        } catch (IOException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
