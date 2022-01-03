from tkinter import messagebox as msg

def about_digi_enve():
    msg.showinfo("About Digital Envelope", "Digital Envelope is a kind of hybrid cryptosystem\nthat combines "
                                           "the convenience of a public-key cryptosystem \nwith the efficiency of a symmetric key cryptosystem to provide better security.")

def about_system():
    msg.showinfo("About the system","Symmetric Algorithm --> AES \n Asymmetric Algorithm --> RSA \n Language --> Python ")

def about_sym():
    msg.showinfo("About Symmetric Algorithm"," Encrypts and decrypts the data using a single private key and\n with a fast speed. \n These single key needs to be shared over network \n ")

def about_asym():
    msg.showinfo("About Asymmetric Algorithm"," Encrypts data using public key\n Decrypts data using private key\n with a slow speed. \n Only public key needs to shared over network \n Private key should be kept safe  ")