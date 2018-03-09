/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

/**
 *
 * @author Deep
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.*;
import OrderInfo.Order;
import OrderInfo.Payment;
import java.io.IOException;
import static java.lang.Math.random;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author Alvin
 */
public class Merchant {

    static X509Certificate bankcertificate;
    static X509Certificate customercertificate;

    static ServerSocket MerchantServer = null;
    static Socket clientSocket = null;
    static Socket Bank = null;
//    static DataOutputStream os = null;
//    static DataInputStream is = null;
    static ObjectOutputStream b_os2 = null; // Bank output stream
    static ObjectInputStream b_is2 = null; // Bank input stream

    static ObjectOutputStream c_os = null; //Client output stream
    static ObjectInputStream c_is = null; //Client input stream

    static String transcationID;
    static CertAndKeyGen keypair = generateKeypair(); // Generating keypair for merchant

    static X509Certificate merchantcertificate = createcertificate(keypair); //Self signed certificate

    static RequestMessage message = new RequestMessage(); //Request Message that needs to be sent around

    static RequestMessage purchasemessage = new RequestMessage();
    
    static Order order;

    public static void openclientserver() throws IOException, ClassNotFoundException {
        MerchantServer = new ServerSocket(9999);
        clientSocket = MerchantServer.accept();
        c_os = new ObjectOutputStream(clientSocket.getOutputStream());
        c_is = new ObjectInputStream(clientSocket.getInputStream());
        System.out.println("Conected");
        RequestMessage initmessage = new RequestMessage();
        initmessage.clearvariables();
        initmessage = (RequestMessage) c_is.readObject();
        if (initmessage.InitStringMessage.contains("Initiate")) {
            connecttobank();
            initiateresponse();
            purchasemessage = (RequestMessage) c_is.readObject();
            if (purchasemessage.InitStringMessage.contains("Purchase Request")) {
                purchaserequestprocessing();
            }
        }
    }

    public static void initiateresponse() throws IOException {
        //assign a unique transcation id 
        transcationID = UUID.randomUUID().toString();
        message.InitStringMessage.add(transcationID);
        message.certificates.add(merchantcertificate);
        message.certificates.add(bankcertificate);
        c_os.writeObject(message);
//        os2.writeObject( merchantcertificate);
//        os2.writeObject( bankcertificate);

    }

    public static void purchaserequestprocessing() throws IOException, ClassNotFoundException {
        customercertificate = purchasemessage.certificates.get(0);
        SealedObject s_order = purchasemessage.sealedobject.get(1);
        // Decrypting the order object using own private key
        try {
            Cipher desCipher2 = Cipher.getInstance("RSA");
            Key sessionkey;
            desCipher2.init(Cipher.UNWRAP_MODE, keypair.getPrivateKey());
            sessionkey = desCipher2.unwrap(purchasemessage.encrypteddata.get(2), "AES", Cipher.SECRET_KEY);

            // Decrypting the payment object using the unwrapped session key
            Cipher desCipher = Cipher.getInstance("AES");
            desCipher.init(Cipher.DECRYPT_MODE, sessionkey);
            order = (Order) s_order.getObject(desCipher);
            System.out.println("Recieved the order from client: " + order.getTransaction_id());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        ///CHECK IF DUAL SIGNATURE IS CORRECT
        //send purchase response 
        c_os.writeUTF("Purchase Processing Completed");
    }

    // Used to verify the digital signature, params are data to be checked and the signature
    public boolean verifySignature(byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(customercertificate.getPublicKey());
        sig.update(data);
        return sig.verify(signature);
    }

    //Payment authorization phase
    public static void authorizationrequest() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {

        message.clearvariables();

        //message for authorization
        message.InitStringMessage.add("500");
        message.InitStringMessage.add(transcationID);

        //generate sessionkey
        KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
        kgen.init(256);
        SecretKey sessionkey = kgen.generateKey();

        Cipher desCipher;
        desCipher = Cipher.getInstance("RSA");

        //encrypt using session key
        desCipher.init(Cipher.ENCRYPT_MODE, sessionkey);
        byte[] encrpyted1 = desCipher.update(message.InitStringMessage.get(0).getBytes());
        byte[] encrpyted2 = desCipher.doFinal(message.InitStringMessage.get(1).getBytes());
        desCipher.init(Cipher.WRAP_MODE, bankcertificate.getPublicKey());
        byte[] wrappedsessionkey = desCipher.wrap(sessionkey);
        message.encrypteddata.add(encrpyted1);
        message.encrypteddata.add(encrpyted2);
        message.encrypteddata.add(wrappedsessionkey);

        //TO DO: SEND PI AND SESSION KEY 1
        message.certificates.add(customercertificate);
        message.certificates.add(merchantcertificate);

        b_os2.writeObject(message);
    }

    public static void responseprocessing() throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher desCipher;
        desCipher = Cipher.getInstance("RSA");
        desCipher.init(Cipher.UNWRAP_MODE, keypair.getPrivateKey());

        byte[] wrappedsessionkey3 = new byte[256];

        b_is2.read(wrappedsessionkey3);
        SecretKey sessionKey3 = (SecretKey) desCipher.unwrap(wrappedsessionkey3, "AES", Cipher.SECRET_KEY);

        byte[] encrpyted = new byte[256];
        b_is2.read(encrpyted);

        desCipher.init(Cipher.DECRYPT_MODE, sessionKey3);
        byte[] decrypted = desCipher.doFinal(encrpyted);

    }

    //Payment Capture Phase
    public static void payementcapturerequest() throws IOException, ClassNotFoundException {

        //message for authorization
        message.InitStringMessage.add("500");
        message.InitStringMessage.add(transcationID);

        try {
            //generate sessionkey
            KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
            kgen.init(256);
            SecretKey sessionkey = kgen.generateKey();

            Cipher desCipher;
            desCipher = Cipher.getInstance("RSA");

            //encrypt using session key
            desCipher.init(Cipher.ENCRYPT_MODE, sessionkey);
            byte[] encrpyted = desCipher.doFinal(message.InitStringMessage.toString().getBytes());

            desCipher = Cipher.getInstance("RSA");
            desCipher.init(Cipher.WRAP_MODE, bankcertificate.getPublicKey());
            byte[] wrappedsessionkey = desCipher.wrap(sessionkey);

            //send stuff
            //message
            b_os2.write(wrappedsessionkey);
            b_os2.write(encrpyted);
        } catch (Exception E) {

        }

        message.certificates.add(merchantcertificate);

        b_os2.writeObject(message);
    }

    public static void processingofresponse() throws IOException, ClassNotFoundException {
        try {
            Cipher desCipher;
            desCipher = Cipher.getInstance("RSA");
            desCipher.init(Cipher.UNWRAP_MODE, keypair.getPrivateKey());

            byte[] wrappedsessionkey3 = new byte[256];

            b_is2.read(wrappedsessionkey3);
            SecretKey sessionKey3 = (SecretKey) desCipher.unwrap(wrappedsessionkey3, "AES", Cipher.SECRET_KEY);

            byte[] encrpyted = new byte[256];
            b_is2.read(encrpyted);

            desCipher.init(Cipher.DECRYPT_MODE, sessionKey3);
            byte[] decrypted = desCipher.doFinal(encrpyted);
        } catch (Exception E) {

        }
    }

    public static void connecttobank() throws IOException, ClassNotFoundException {
        Bank = new Socket("127.0.0.1", 1000);
        b_is2 = new ObjectInputStream(Bank.getInputStream());
        b_os2 = new ObjectOutputStream(Bank.getOutputStream());
        b_os2.writeUTF("Connected to Bank");
        b_os2.writeUTF("Send your certificate");
        bankcertificate = (X509Certificate) b_is2.readObject();
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

    public static CertAndKeyGen generateKeypair() {
        CertAndKeyGen kpair = null;
        try {
            kpair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            kpair.generate(2048);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kpair;
    }

    public static void close_servers() {
        try {
            //Close bank sockets
            b_os2.close();
            b_is2.close();
            Bank.close();

            // Close Client sockets
            c_os.close();
            c_is.close();
            clientSocket.close();
            MerchantServer.close();
        } catch (IOException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void main(String args[]) throws ClassNotFoundException, InterruptedException {
        //Creating certificate and keypair. You can use keypair to get public and private key

        try {
            openclientserver();
        } catch (IOException ex) {
            Logger.getLogger(Merchant.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
