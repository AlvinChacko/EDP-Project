# SET-Protocol-Application
Every day millions of electronic transactions occur around the world, where users shop everyday things online. It is noted that about 80% of Americans are online shoppers. Consequently, credit card fraud is rising every day, 46% of Americans have been victim to credit card fraud. Therefore, there is a need now to make online transactions more secure than ever before. Secure Transaction Protocol (SET) provides solution to this by, encrypting critical information over the internet that separates the merchant from credit card information. Hence, customers when shopping online can be rest assured that their credit card info won’t be used wrongly. 

## Approach
While SET protocol is implemented in Ecommerce environments, our approach was to design 3 components to simulate the protocol. The User interface is design in SWING and the implementation is in JAVA. 
1.	Client – This is to simulate the browser in which client will connect to the Merchant. The user interface involves a products page along with user provided credit card information.
2.	Merchant – This simulates the server on the merchant’s side. This interface contains just logging information to see what’s been passes around
3.	Bank – This simulates the payment gateway in which client credit card numbers are verified and captures the payment. In this interface, the messages received and send are printed to the screen for visualization. 

3 phases were implemented to completely simulate the protocol and ensure that the data is correctly identified in each component. 
- Purchase Request Phase: This phase involves client initiating a request and receiving response from merchant to verify the authenticity of the merchant.   
- Payment Authorization Phase: Using the purchase request the merchant tries to authorize the transaction and validate the client payment details with the payment gateway.  A copy of the payment authorization response is sent back to the client for safe keeping
- Payment Capture Phase: This final phase in the protocol is to capture the payment. In this phase, the Merchant requests payment from the payment gateway and may occur sometime after the transaction has occurred.
