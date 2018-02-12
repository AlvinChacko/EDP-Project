/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package OrderInfo;

import java.util.ArrayList;

/**
 *
 * @author Alvin
 */
public class Order {
    private int transaction_id;
    private double tax, total;
    private int subtotal;
    private ArrayList <String> products = new ArrayList<>();
    private String Orderstatus, paymentstatus;

    public Order(int transaction_id) {
        this.transaction_id = transaction_id;
        Orderstatus = "Pending";
        paymentstatus = "Pending";
    }
    

    public int getTransaction_id() {
        return transaction_id;
    }

    public void setTransaction_id(int transaction_id) {
        this.transaction_id = transaction_id;
    }

    public double calculateTotal() {
        calculateTax();
        total = subtotal + tax;
        return  total;
    }

    public void calculateTax() {
        tax = subtotal * 0.13;
    }
    

    public int getSubtotal() {
        return subtotal;
    }

    public void setSubtotal(int subtotal) {
        this.subtotal = subtotal;
    }

    public String getOrderstatus() {
        return Orderstatus;
    }

    public void setOrderstatus(String Orderstatus) {
        this.Orderstatus = Orderstatus;
    }

    public String getPaymentstatus() {
        return paymentstatus;
    }

    public void setPaymentstatus(String paymentstatus) {
        this.paymentstatus = paymentstatus;
    }

    public ArrayList <String> getProducts() {
        return products;
    }

    public void addProducts(String product, int amount) {
        products.add(product);
        subtotal = subtotal+amount;
    }
    
    
}
