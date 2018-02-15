/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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

import java.io.PrintStream;
import java.util.Scanner;
import java.io.*;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import static sun.security.krb5.Confounder.bytes;

/**
 *
 * @author Bhatt
 */
public class Bank {

    static PrivateKey myPR;
    private static byte[] bytes;
    static PublicKey merPU;

    public static void openbankserver() throws IOException {
        ServerSocket BankServer = null;
        Socket BankSocket = null;
        BankServer = new ServerSocket(1000);
        BankSocket = BankServer.accept();
        DataOutputStream os = new DataOutputStream(BankSocket.getOutputStream());
        DataInputStream is = new DataInputStream(BankSocket.getInputStream());
        System.out.println(is.readUTF());

        //  os.close();
        //is.close();
        // BankSocket.close();
        // BankServer.close();
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

//    public static void openMessage(String PRkey, File inputFile, File outputFile)
//    {
//         Key key =
//         cipherin.init(Cipher.DECRYPT_MODE, myPR);
//            ib= Toread.readUTF();
//            bytes=decoder.decodeBuffer(ib);
//            System.out.println("");
//            System.out.println("The cipher text of Message 1 received from A: "+bytes);
//            byte [] cipherText = cipherin.doFinal(bytes);
//            System.out.println("The clear text of Message 1 received from A: "+new String(cipherText));
//            int old_or= new String(cipherText).indexOf("||");
//            String hisNonce=new String(cipherText).substring(0,old_or);
//         
//        
//        // variable referencing the encrypted messsage
//        // varibale referncing the message with ecnryotion method to open the encrypted message
//        // storing the amount information referencing a variable 
//        // variable referencing the message with encryption method to open the encrypted messahe bycustomer
//        // storing the aaccout information referencing a variable
//        // comparing amount and account wiht instance from array list 
//        // if amount is less than balance than valid otherwise non valid 
//       
//        
//        
//    }
    public static void authRequest() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        BASE64Decoder decoder = new BASE64Decoder();
        Socket bSocket = null;
        DataInputStream Toread = new DataInputStream(bSocket.getInputStream());

        Cipher cipherin = Cipher.getInstance("RSA");
        Cipher testcipher = Cipher.getInstance("RSA");
        String ib;

        cipherin.init(Cipher.DECRYPT_MODE, myPR);   //Initializes this cipher with a key.
        ib = Toread.readUTF();                //reads binary value
        bytes = decoder.decodeBuffer(ib);      //decodes value in character form
        System.out.println("");
        System.out.println("The cipher text of Message 1 received from Merchant: " + bytes);
        byte[] cipherText = cipherin.doFinal(bytes); //Finishes a multiple-part encryption or decryption operation, depending on how this cipher was initialized
        System.out.println("The clear text of Message 1 received from Merchant: " + new String(cipherText));

        //  int old_or= new String(cipherText).indexOf("||");
    }

    public static void authResponse() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        String ob = null;
        Socket aSocket = null;
        Cipher cipherout = Cipher.getInstance("RSA");
        DataOutputStream Towr = new DataOutputStream(aSocket.getOutputStream());
        BASE64Encoder encoder = new BASE64Encoder();
        System.out.println("The clear text of Message 2 sent to Merchant: " + ob);
        cipherout.init(Cipher.ENCRYPT_MODE, merPU); //encrypting usingmerchants public key
        byte[] cipherText = cipherout.doFinal(ob.getBytes());  //converting to ciphertext
        Towr.writeUTF(encoder.encode(cipherText)); //writing encoded cipher text to the socket
        System.out.println("The cipher text of Message 2 sent to Merchant: " + cipherText);
    }

//    public static void sendMessage()
//    {
//       System.out.println("The clear text of Message 2 sent to A: "+ob);
//            cipherout.init(Cipher.ENCRYPT_MODE, hisPU);
//            cipherText = cipherout.doFinal(ob.getBytes());
//            writer.writeUTF(encoder.encode(cipherText));
//            System.out.println("The cipher text of Message 2 sent to A: "+cipherText);
//        //variable referencing recived message
//        //using banks private key to decrypt
//        //using session keyto decrypt message from merchant and storing in variable
//        // comapring amount information with customers current balance
//        
//    }
    public static void main(String args[]) throws IOException, ClassNotFoundException {
//Creating certificate and keypair. You can use keypair to get public and private key

        List<Customerr> custList = new ArrayList<Customerr>();
        Customerr customer1 = new Customerr();
        customer1.setAccountNum(123);
        customer1.setBalance(500);
        customer1.setName("Kali");

        List<Merchantt> merchList = new ArrayList<Merchantt>();
        Merchantt merchant1 = new Merchantt();
        merchant1.setmAccountNum(123);
        merchant1.setmBalance(500);
        merchant1.setmName("Eva Corp");

        //  Cipher cipher = Cipher.getInstance("AES"); //creates a Cipher instance using the encryption algorithm called AES
        //cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // instantiating a cipher you can append its mode to the name of the encryption algorithm. For instance, to create an AES Cipher instance using Cipher Block Chaining (CBC) 
        CertAndKeyGen keypair = generateKeypair();
        X509Certificate Bank_certificate = createcertificate(keypair);
        try {
            openbankserver();
        } catch (IOException e) {
            System.out.println(e);
        }

    }

    class Customerr {

        private String Name;
        private int AccountNum;
        private int Balance;

        public String getName() {
            return this.Name;
        }

        public int getAccountNum() {
            return this.AccountNum;
        }

        public boolean setName(String name) {
            this.Name = name;
            return true;
        }

        public boolean setAccountNum(int accountNum) {
            this.AccountNum = accountNum;
            return true;
        }

        public int getBalance() {
            return this.Balance;
        }

        public boolean setBalance(int balance) {
            this.Balance = balance;
            return true;
        }
    }

    class Merchantt {

        private String mName;
        private int mAccountNum;
        private int mBalance;

        public int getmAccountNum() {
            return this.mAccountNum;
        }

        public boolean setmAccountNum(int maccountNum) {
            this.mAccountNum = maccountNum;
            return true;
        }

        public boolean setmName(String mname) {
            this.mName = mname;
            return true;
        }

        public String getmName() {
            return this.mName;
        }

        public int getmBalance() {
            return this.mBalance;
        }

        public boolean setmBalance(int mbalance) {
            this.mBalance = mbalance;
            return true;
        }

    }

//You create a symmetric key much as you create a key pair. You use a factory method from the KeyGenerator 
//class and pass in the algorithm as a String. When you call the generateKey() method, you get back an object 
//that implements the Key interface instead of the KeyPair interface.
//SecretKey key =
//     KeyGenerator.getInstance("DES").generateKey();

