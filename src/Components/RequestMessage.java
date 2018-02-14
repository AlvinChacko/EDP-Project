/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Components;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 *
 * @author Alvin
 */
public class RequestMessage {

    protected ArrayList<X509Certificate> certificates = new ArrayList<>();
    protected ArrayList InitStringMessage = new ArrayList<>();
    protected ArrayList IntNumbers = new ArrayList<>();
    protected ArrayList<MessageDigest> messagedigest =  new ArrayList<>();

    /**
     * @return the certificates
     */
    public ArrayList<X509Certificate> getCertificates() {
        return certificates;
    }

    /**
     * @return the InitStringMessage
     */
    public ArrayList getInitStringMessage() {
        return InitStringMessage;
    }

    /**
     * @return the IntNumbers
     */
    public ArrayList getIntNumbers() {
        return IntNumbers;
    }

    /**
     * @return the messagedigest
     */
    public ArrayList<MessageDigest> getMessagedigest() {
        return messagedigest;
    }

    public void clearvariables(){
        certificates.clear();
        InitStringMessage.clear();
        IntNumbers.clear();
        messagedigest.clear();
    }
    
}
