/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package OrderInfo;

/**
 *
 * @author Alvin
 */
public class Payment {
    private String credicardnumber;
    private int cvv;
    private String Fname;
    private String Lname;
    private String address;
    private int authorizeammount=0;
    private String expirydate;
    private String paymentstatus;
    
    public Payment(String credicardnumber, String Fname, String Lname, String address) {
        this.credicardnumber = credicardnumber;
        this.Fname = Fname;
        this.Lname = Lname;
        this.address = address;
        paymentstatus = "Pending";
    }

    public void setCredicardnumber(String credicardnumber) {
        this.credicardnumber = credicardnumber;
    }

    public void setCvv(int cvv) {
        this.cvv = cvv;
    }


    public void setFname(String Fname) {
        this.Fname = Fname;
    }

    public void setLname(String Lname) {
        this.Lname = Lname;
    }


    public void setAddress(String address) {
        this.address = address;
    }


    public int getAuthorizeammount() {
        return authorizeammount;
    }


    public void setAuthorizeammount(int authorizeammount) {
        this.authorizeammount = authorizeammount;
    }

    public String getFname() {
        return Fname;
    }

    public String getLname() {
        return Lname;
    }

    public String getAddress() {
        return address;
    }

    public String getExpirydate() {
        return expirydate;
    }

    public void setExpirydate(String expirydate) {
        this.expirydate = expirydate;
    }

    public String getPaymentstatus() {
        return paymentstatus;
    }

    public void setPaymentstatus(String paymentstatus) {
        this.paymentstatus = paymentstatus;
    }
    
    
}
