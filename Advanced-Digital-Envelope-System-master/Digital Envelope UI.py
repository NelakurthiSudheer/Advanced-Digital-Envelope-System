import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import Menu
from tkinter import Toplevel
import filecmp
import menu_func
import rsaGenerator as rsagen
import os
import sys
from tkinter import messagebox as msg
import aesMain as aes
import rsaEncrypt
import rsaDecrypt
import tooltips as tt
import aespassword_generator as aesgen
import getHash as gh
import pkcs_pad as pk
import time
from multiprocessing import Process

def aes_encrypt(message_loc, aeskey, out_path_message):
    data = aes.encrypt(message_loc, aeskey,'cbc')
    with open(out_path_message, 'wb') as f:
        f.write(bytes(data))

def aes_decrypt(cryp_loc,decrypted_key,out_path_decrypted_message):
    decrypted_data = aes.decrypt(cryp_loc, decrypted_key,'cbc')
    for num in reversed(decrypted_data):
        if num == 0:
            decrypted_data = decrypted_data[:len(decrypted_data) - 1]
        else:
            break
    # print(decrypted_data)
    with open(out_path_decrypted_message, 'wb') as ff:
        ff.write(bytes(decrypted_data))


if __name__ == '__main__':

    #from threading import Thread
    #from PIL import Image,ImageTk

    root = tk.Tk()
    root.title("Digital Envelope")
    # root.resizable(False,False)
    rsa_yesno = tk.IntVar()



    def fontsize_12b(x):
        # font size for label
        x.config(font=("Times",12,"bold"))

    def fontsize_13b(x):
        # font size for label
        x.config(font=("Times",13,"bold"))


    def fontsize_12t(x):
        # font size for label
        x.config(font=("Times",12))

    def fontsize_10(x):
        x.config(font=("Courier",10))

    def fontsize_12(x):
        x.config(font=("Courier", 12))

    def fontsize_13(x):
        x.config(font=("Times", 13))

    en_count = tk.IntVar()
    en_count.set(0)
    de_count = tk.IntVar()
    de_count.set(0)
    rsa_keylen = tk.IntVar()

    def _create():
        #wid_destroy(main_frame,rsagen_frame,decision_frame)
        func_id.set(1)
        root.withdraw()
        encrypt_form()
        en_count.set(1)

    def _open():
        #wid_destroy(main_frame,rsagen_frame,decision_frame)
        func_id.set(2)
        root.withdraw()
        decrypt_form()
        de_count.set(1)

    def rsagenerator():
        keylength = rsa_keylen.get()
        # print(keylength)
        # print(type(keylength))
        path = filedialog.askdirectory()
        if path!='':
            start = time.time()
            output_pub = os.path.join(path, 'Public Key.txt')
            output_priv = os.path.join(path, 'Private Key.txt')
            publicKey, privateKey = rsagen.generateKey(keylength)
            with open(output_pub, 'w') as f:
                f.write('%s,%s,%s' % (keylength, publicKey[0], publicKey[1]))

            with open(output_priv, 'w') as f:
                f.write('%s,%s,%s' % (keylength, privateKey[0], privateKey[1]))

            duration = round((time.time()-start),2)
            msg.showinfo('RSA key duration','The duration for RSA key generation is '+str(duration))

            msg.showinfo('RSA Key Generator', 'Key Generation finished.')

    def __menu__():
        root.resizable(False,False)

        main_frame = ttk.Frame(root)
        main_frame.grid(column=0, row=0, padx=10, pady=10)

        rsagen_frame = ttk.LabelFrame(root, text="RSA generator")
        rsagen_frame.grid(column=0, row=1, padx=10, pady=10, sticky=tk.W)

        decision_frame = ttk.LabelFrame(root, text="Facts about this sytem", width=100)
        decision_frame.grid(column=0, row=2, padx=10, pady=10, sticky=tk.W)

        greeting = tk.Message(main_frame,text="Welcome to the digital envelope system...")
        greeting.config(fg='blue',font=('times',16,'italic'),width=500)
        greeting.grid(column=1, row=0, padx=15, pady=20,sticky=tk.W)

        advice = "A pair of RSA keys are needed. Do you have it? "
        advice_lab = ttk.Label(rsagen_frame, text=advice)
        fontsize_13(advice_lab)
        advice_lab.grid(column=0,row=0,padx=30,pady=20,columnspan=2,sticky=tk.W)

        rsa_gene_button = ttk.Button(rsagen_frame, width=18, text="RSA Key Generator", command=rsagenerator)
        rsa_gene_button.grid(column=2, row=0, padx=5, pady=20, ipadx=10, ipady=15, sticky=tk.E)

        key_length = ttk.Label(rsagen_frame, text="Choose the length of RSA key: ")
        fontsize_13(key_length)
        key_length.grid(column=0,row=1,padx=10,pady=20)

        key_choice = ttk.Combobox(rsagen_frame,width=10,height=10,textvariable=rsa_keylen,state="readonly")
        key_choice['values'] = (1024,2048,4096)
        key_choice.grid(column=2,row=1,ipadx=8,ipady=5,padx=30,pady=20,sticky=tk.W)
        key_choice.current(0)

        ins = "1.   To use the system, first you need to have a pair of RSA keys called public key and private key.\n      If you don’t have one, generate it from the RSA key generator. You don’t need to generate it\n      frequently whenever you use the system and can reuse the previous RSA keys."
        fact1 = ttk.Label(decision_frame, text=ins)
        fontsize_13(fact1)
        fact1.grid(column=0, row=0,pady=10,columnspan=3,sticky=tk.W)
        ins = "2.   Second, you need to exchange the public key with the person you want to communicate with."
        fact2 = ttk.Label(decision_frame, text=ins)
        fontsize_13(fact2)
        fact2.grid(column=0, row=1, pady=10 ,columnspan=3,sticky=tk.W)
        ins = "3.   Third, you must keep your private key secret. Don’t reveal it to anyone."
        fact3 = ttk.Label(decision_frame, text=ins)
        fontsize_13(fact3)
        fact3.grid(column=0, row=2, pady=10 ,columnspan=3,sticky=tk.W)
        ins = "4.   The RSA key used in this system have a specific format. If you use the other key formats\n      generated from other system, you will got some kind of error."
        fact4 = ttk.Label(decision_frame, text=ins)
        fontsize_13(fact4)
        fact4.grid(column=0, row=3, pady=10, columnspan=3, sticky=tk.W)
        ins = '5.   "Create Digital Envelope" button is for securing your data and "Opening Digital Envelope"\n      button is for decrypting the data sent from others. '
        fact5 = ttk.Label(decision_frame, text=ins)
        fontsize_13(fact5)
        fact5.grid(column=0, row=4, pady=10, columnspan=3, sticky=tk.W)

        create_enve = ttk.Button(decision_frame, text="Create Digital Envelope",command=_create)
        create_enve.grid(column=0, row=5,padx=10,ipadx=25,pady=40,ipady=15)

        open_enve = ttk.Button(decision_frame, text="Open Digital Envelope", command=_open)
        open_enve.grid(column=1, row=5, pady=40,ipadx=25,ipady=15,sticky=tk.E)

    __menu__()
    # variables for encrypt
    message_loc = tk.StringVar()
    send_pub_loc = tk.StringVar()
    send_priv_loc = tk.StringVar()
    large_font = ('Verdana', 13)
    sav_en_loc = tk.StringVar()
    #aeskey = tk.StringVar()
    tooltip_yesno = tk.IntVar()
    rsakey_yesno = tk.IntVar()
    keylen = tk.IntVar()
    func_id = tk.IntVar()
    aeskey = ''
    # no for rsa key generator

    cryp_loc = tk.StringVar()
    #cryp_key_loc = tk.StringVar()
    rece_priv_loc = tk.StringVar()
    rece_pub_loc = tk.StringVar()
    sav_de_lc = tk.StringVar()


    def back_menu():
        if func_id.get() == 1:
            encryp_form.withdraw()
            root.update()
            root.deiconify()
        elif func_id.get() == 2:
            decryp_form.withdraw()
            root.update()
            root.deiconify()

    def encrypt_form():
        if en_count.get() == 0:
            func_id.set(1)
            global encryp_form
            encryp_form = Toplevel(root)
            encryp_form.resizable(False,False)
            encryp_form.iconbitmap('email.ico')
            encryp_form.title('Creating Digital Envelope')
            made_menu(encryp_form)

            mess_frame = ttk.LabelFrame(encryp_form, text="Message file")
            mess_frame.grid(column=0, row=1, padx=(60, 80), pady=15, sticky=tk.W)

            aes_frame = ttk.LabelFrame(encryp_form, text="AES Key")
            aes_frame.grid(column=0, row=2, padx=(60, 80), pady=15, sticky=tk.W)

            rsapub_frame = ttk.LabelFrame(encryp_form, text="RSA Keys")
            rsapub_frame.grid(column=0, row=3, padx=(60, 80), pady=15, sticky=tk.W)

            manaul_make_frame = ttk.Frame(encryp_form)
            manaul_make_frame.grid(column=0, row=0, padx=30, pady=15)
            out_form = ttk.LabelFrame(encryp_form, text="Output")
            out_form.grid(column=0, row=4, columnspan=2, padx=(60, 80), pady=10, sticky=tk.W)
            button_frame = ttk.Frame(encryp_form)
            button_frame.grid(column=0,row=5,columnspan=3,padx=(60, 80), pady=10, sticky=tk.W)

            manual_for_make = " Creating Digital Envelope"
            manual_mes = tk.Message(manaul_make_frame, text=manual_for_make,width=700)
            manual_mes.config( fg='blue',font=('times', 16, 'italic'))
            manual_mes.grid(column=0, row=0, padx=4, pady=12, sticky=tk.W,columnspan=7)

            aes_key_len = ttk.Label(aes_frame,text="Choose the length of the key:")
            fontsize_13(aes_key_len)
            aes_key_len.grid(column=0, row=0, padx=35,pady=(12,20),sticky=tk.W)
            len_choice = ttk.Combobox(aes_frame,width=13,height=8,textvariable=keylen,state='readonly')
            len_choice['values'] = (128,192,256)
            len_choice.grid(column=1, row=0,padx=35,pady=(12,20),ipady=8,ipadx=8)
            len_choice.current(0)
            tt.create_Tooltip(len_choice,'Choose the length of the key for AES operation')
            # aeskey_entered = ttk.Entry(aes_frame, width=50,font=fontsize_12, textvariable=aeskey,state='readonly')
            # aeskey_entered.grid(column=0, row=1,padx=8,pady=12,ipady=7,sticky=tk.EW)
            # aespassword_button = ttk.Button(aes_frame, text="AES Key Generator", command=aes_pass_generator)
            # aespassword_button.grid(column=1, row=1, padx=8,pady=12,ipady=7,ipadx=10)

            message_file = "Browse the location of the file : "
            mess_label=ttk.Label(mess_frame,text=message_file)
            fontsize_13(mess_label)
            mess_label.grid(column=0,row=0,padx=4,pady=12,sticky=tk.W)
            mes_loc_entered = ttk.Entry(mess_frame, width= 30, font=fontsize_12,textvariable = message_loc)
            mes_loc_entered.grid(column=1,row=0,padx=4,pady=12,ipady=7,sticky=tk.EW)
            browse_button = ttk.Button(mess_frame,text="..",command=browse_message,width=3)
            browse_button.grid(column=2, row=0,sticky=tk.W)

            rsa_file = "Browse the public key of the receiver :"
            rsa_label = ttk.Label(rsapub_frame,text=rsa_file)
            fontsize_13(rsa_label)
            rsa_label.grid(column=0, row=0,padx=4,pady=8,sticky=tk.W)
            pub_loc_entered = ttk.Entry(rsapub_frame,width= 30, font=fontsize_12,textvariable = rece_pub_loc)
            pub_loc_entered.grid(column=1,row=0,padx=4,pady=8,ipady=7,sticky=tk.EW)
            browse_button_pub = ttk.Button(rsapub_frame, text="..", command=browse_pub_rece,width=3)
            browse_button_pub.grid(column=2, row=0,sticky=tk.E)

            rsa_file = "Browse the private key of the sender :"
            rsa_label2 = ttk.Label(rsapub_frame, text=rsa_file)
            fontsize_13(rsa_label2)
            rsa_label2.grid(column=0, row=1, padx=4, pady=8,sticky=tk.W)
            priv_loc_entered = ttk.Entry(rsapub_frame, width=30, font=fontsize_12, textvariable=send_priv_loc)
            priv_loc_entered.grid(column=1, row=1, padx=4, pady=8, ipady=7, sticky=tk.EW)
            browse_button_pub = ttk.Button(rsapub_frame, text="..", command=browse_priv_send, width=3)
            browse_button_pub.grid(column=2, row=1, sticky=tk.E)

            sav_file_label = ttk.Label(out_form,text="Browse the folder to save the output files :")
            fontsize_13(sav_file_label)
            sav_file_label.grid(column=0,row=0,padx=4,pady=8,sticky=tk.W)
            sav_file_entered = ttk.Entry(out_form, width= 30, font=fontsize_12, textvariable = sav_en_loc)
            sav_file_entered.grid(column=1,row=0,padx=4,pady=8,ipady=7,sticky=tk.EW)
            browse_button_pub = ttk.Button(out_form,text="..",command=browse_sav_file, width=3)
            browse_button_pub.grid(column=2,row=0,sticky=tk.E)

            mak_enve = ttk.Button(button_frame, text="Create an Envelope", width=10, command=_encrypt_mes)
            mak_enve.grid(column=0, row=0, ipadx=30,padx=45, ipady=15, pady=(30,20))

            menu_back = ttk.Button(button_frame, text="Back to Main Menu", width=10, command=back_menu)
            menu_back.grid(column=1, row=0, ipadx=30, padx=45,ipady=15, pady=(30,20))

            exit_button = ttk.Button(button_frame, text="Exit", width=10,command=_quit)
            exit_button.grid(column=2, row=0, ipadx=20, padx=45, ipady=15, pady=(30,20))

            #tt.create_Tooltip(aeskey_entered,
                              #'Key length of 128 will be 16 symbols.\nKey Length of 192 will be 24 symbols.\nKey Length of 256 will be 32 symbols.')
            tt.create_Tooltip(mes_loc_entered, 'This must be the file you want to secure')
            tt.create_Tooltip(browse_button, 'Browse button')
            tt.create_Tooltip(pub_loc_entered,
                              "The public key file(from receiver) format must be key length and two large numbers.\nOtherwise it won't work.")
            tt.create_Tooltip(priv_loc_entered,
                              "The private key file(from sender) format must be key length and two large numbers.\nOtherwise it won't work.")
            tt.create_Tooltip(sav_file_entered, 'Choose the folder you want to keep the output file.')

        elif en_count.get() > 0:
            root.withdraw()
            encryp_form.update()
            encryp_form.deiconify()


    def aes_pass_generator():
        keysize = 0
        val = keylen.get()
        if val == 128:
            keysize = 16
        elif val == 192:
            keysize = 24
        elif val == 256:
            keysize = 32
        aeskey = aesgen.pass_gen(keysize)
        return aeskey

    def browse_message():
        filename = filedialog.askopenfilename( title="Choose the location of your message", filetypes=(("text files","*.txt"),("all files","*.*")))
        message_loc.set(filename)
    def browse_pub_rece():
        filename = filedialog.askopenfilename( title="Choose the location of the text file containing the receiver's public key..", filetypes=(("text files","*.txt"),("all files","*.*")))
        rece_pub_loc.set(filename)
    def browse_pub_send():
        filename = filedialog.askopenfilename( title="Choose the location of the text file containing the sender's public key..", filetypes=(("text files","*.txt"),("all files","*.*")))
        send_pub_loc.set(filename)

    def browse_cryp():
        filename = filedialog.askdirectory()
        cryp_loc.set(filename)
    # def browse_cryp_key():
    #     filename= filedialog.askopenfilename(title="Browse the encrypted key file", filetypes=(("text files","*.txt"),("all files","*.*")))
    #     cryp_key_loc.set(filename)
    def browse_priv_send():
        filename = filedialog.askopenfilename( title="Choose the location of the text file containing the sender's prviate key ", filetypes=(("text files","*.txt"),("all files","*.*")))
        send_priv_loc.set(filename)
    def browse_priv_rece():
        filename = filedialog.askopenfilename( title="Choose the location of the text file containing the receiver's prviate key ", filetypes=(("text files","*.txt"),("all files","*.*")))
        rece_priv_loc.set(filename)
    def browse_sav_file():
        filename = filedialog.askdirectory()
        sav_en_loc.set(filename)
    def browse_sav_rece():
        filename = filedialog.askdirectory()
        sav_de_lc.set(filename)

    def _quit():
        root.quit()
        root.destroy()
        sys.exit()


    origin_txt = tk.StringVar()
    decrypted_txt = tk.StringVar()

    def browse_origin_txt():
        filename = filedialog.askopenfilename(title="Original file",
                                              filetypes=(("text files", "*.txt"), ("all files", "*.*")))
        origin_txt.set(filename)


    def browse_decrypted_txt():
        filename = filedialog.askopenfilename(title="Decrypted file",
                                              filetypes=(("text files", "*.txt"), ("all files", "*.*")))
        decrypted_txt.set(filename)

    def check_accuracy():
        chk = filecmp.cmp(origin_txt.get(),decrypted_txt.get())
        if chk:
            result_label.configure(text='The contents of the two file are the same.')
        else:
            result_label.configure(text='The contents of the two file are not the same.')
    def close_accuracy():
        accurate_form.withdraw()


    def _check_accuracy():
        global accurate_form
        accurate_form = Toplevel(root)
        accurate_form.resizable(False, False)
        accurate_form.iconbitmap('email.ico')
        accurate_form.title('Checking Accuracy')
        #accurate_form.lift()
        accurate_form.attributes("-topmost",True)

        title = "Checking accuracy of the file"
        manual_mes = tk.Message(accurate_form, text=title, width=700)
        manual_mes.config(fg='blue', font=('times', 16, 'italic'))
        manual_mes.grid(column=1, row=0, padx=4, pady=12, sticky=tk.W, columnspan=7)

        label1 = ttk.Label(accurate_form,text="Enter the original file: ")
        fontsize_13(label1)
        label1.grid(column=0,row=1,padx=8,pady=8)
        original_file = ttk.Entry(accurate_form,width=40, font=fontsize_12, textvariable = origin_txt)
        original_file.grid(column=1,row=1,padx=8,pady=8)
        browse_origin_file = ttk.Button(accurate_form, text="..", command=browse_origin_txt, width=3)
        browse_origin_file.grid(column=2, row=1,padx=8,pady=8 )

        label2 = ttk.Label(accurate_form, text="Enter the decrypted file: ")
        fontsize_13(label2)
        label2.grid(column=0, row=2, padx=8, pady=8)
        decrypted_file = ttk.Entry(accurate_form, width=40, font=fontsize_12, textvariable=decrypted_txt)
        decrypted_file.grid(column=1, row=2, padx=8, pady=8)
        browse_decrypted_file = ttk.Button(accurate_form, text="..", command=browse_decrypted_txt, width=3)
        browse_decrypted_file.grid(column=2, row=2, padx=8, pady=8)

        chk_accu_button = ttk.Button(accurate_form,text="Check it",command=check_accuracy)
        chk_accu_button.grid(column=1,row=3,padx=8,pady=(20,8),sticky=tk.W)
        close_button = ttk.Button(accurate_form,text="Back",command=close_accuracy)
        close_button.grid(column=1,row=3,padx=8,pady=(20,8),sticky=tk.E)

        global result_label
        result_label = ttk.Label(accurate_form,text='')
        fontsize_13(result_label)
        result_label.grid(column=1,row=4,padx=10,pady=10)

    def made_menu(root):
        menu_bar = Menu(root)
        root.config(menu= menu_bar)

        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Check Accuracy", command=_check_accuracy)
        file_menu.add_separator()
        file_menu.add_command(label="Exit",command=_quit)
        menu_bar.add_cascade(label="File",menu=file_menu)

        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Digital Envelope",command=menu_func.about_digi_enve)
        help_menu.add_separator()
        help_menu.add_command(label="System", command=menu_func.about_system)
        help_menu.add_separator()
        algo_menu = Menu(help_menu,tearoff=0)
        algo_menu.add_command(label="Symmetric",command=menu_func.about_sym)
        algo_menu.add_separator()
        algo_menu.add_command(label="Asymmetric",command=menu_func.about_asym)
        help_menu.add_cascade(label="Algorithms ", menu=algo_menu)
        menu_bar.add_cascade(label="About",menu=help_menu)


    def _encrypt_mes():
        if message_loc.get() and rece_pub_loc.get() and send_priv_loc.get() and sav_en_loc.get():
            start = time.time()
            file_check = check_exist_file()
            directory_check = check_exist_path()
            aeskey = aes_pass_generator()
            encoded_data = pk.pkcs(rece_pub_loc.get(), aeskey, message_loc.get())
            if file_check and directory_check:
                out_path = os.path.abspath(sav_en_loc.get())
                out_path_message = os.path.join(out_path, 'encrypted_file.txt')
                p1e = Process(target=aes_encrypt, args=(message_loc.get(), aeskey, out_path_message,))
                p1e.start()

                out_path_key = os.path.join(out_path, 'encrypted_key.txt')
                encryptedKeyContent = rsaEncrypt.encryptKey(rece_pub_loc.get(), encoded_data)
                encryptedKeyContent = rsaEncrypt.encryptKey(send_priv_loc.get(), encryptedKeyContent)
                with open(out_path_key, 'w') as ff:
                    ff.write(encryptedKeyContent)

                p1e.join()
                duration = time.time() - start
                msg.showinfo('Duration','Duration for the whole process is '+str(round(duration,2))+' seconds')
                #msg.showinfo('Output File','The output file will be two file called encrypted_textfile.txt and encrypted_keydigest.txt in your chosen folder.')
        else:
            msg.showerror('Warning','Please fill the form completely')




    def _open_mes():
        out_path = os.path.abspath(sav_de_lc.get())
        out_path_cryp = os.path.abspath(cryp_loc.get())
        out_path_decrypted_message = os.path.join(out_path, 'decrypted_data.txt')
        encryp_loc = os.path.join(out_path_cryp, 'encrypted_file.txt')
        encryp_key_loc = os.path.join(out_path_cryp, 'encrypted_key.txt')
        if cryp_loc.get() and  rece_priv_loc.get() and send_pub_loc.get() and sav_de_lc.get():
            start = time.time()
            file_check = check_exist_file()
            folder_check = check_exist_path()
            if file_check and folder_check:

                decrypted_key = rsaDecrypt.readFromFileAndAuthenticateKey(encryp_key_loc, send_pub_loc.get())
                encoded_data = rsaDecrypt.DecryptAESKey(decrypted_key,rece_priv_loc.get())
                decrypted_key = pk.extract_key(encoded_data)
                p1d = Process(target=aes_decrypt,args=(encryp_loc,decrypted_key,out_path_decrypted_message,))
                p1d.start()

                exthash = pk.extract_hash(encoded_data)


                # decrypted_data = aes.decrypt(cryp_loc.get(), decrypted_key)
                # for num in reversed(decrypted_data):
                #     if num == 0:
                #         decrypted_data = decrypted_data[:len(decrypted_data) - 1]
                #     else:
                #         break
                # #print(decrypted_data)
                # with open(out_path_decrypted_message, 'wb') as ff:
                #     ff.write(bytes(decrypted_data))
                p1d.join()
                decrypted_data_hash = gh.gethash(out_path_decrypted_message)
                hash_equal = exthash == decrypted_data_hash
                duration = str(round(time.time()-start,2))
                if hash_equal:
                    msg.showinfo('Message Integrity','The digest of original file and that of decrypted file are the same.')
                else:
                    msg.showwarning('Message Integrity','The digest of original file and that of decrypted file are not the same.This means the data may be altered in transmission.')
                msg.showinfo('Duration','Duration for the whole process is '+duration+' seconds')

                #msg.showinfo('Output File','The output file will be the file called decrypted_data.txt in your chosen folder.')

        else:
            msg.showerror('Warning','Please fill the form completely')

    def decrypt_form():
        if de_count.get() == 0:
            func_id.set(2)
            global decryp_form
            decryp_form = Toplevel(root)
            decryp_form.resizable(False, False)
            decryp_form.iconbitmap('email.ico')
            decryp_form.title("Opening Digital Envelope")
            made_menu(decryp_form)
            #decryp_form.grid(column=0,row=0,sticky=tk.W)

            manaul_open_frame = ttk.Frame(decryp_form)
            manaul_open_frame.grid(column=0, row=0, padx=30, pady=15)

            crypfile_form = ttk.LabelFrame(decryp_form, text="Encrypted File & AES Key")
            crypfile_form.grid(column=0, row=1, padx=(60, 100), pady=10, sticky=tk.W)

            priv_form = ttk.LabelFrame(decryp_form, text="RSA Keys")
            priv_form.grid(column=0, row=2, padx=(60, 100), pady=10, sticky=tk.W)

            out_form_open = ttk.LabelFrame(decryp_form, text="Output")
            out_form_open.grid(column=0, row=3, columnspan=2, padx=(60, 100), pady=10, sticky=tk.W)

            button_frame = ttk.Frame(decryp_form)
            button_frame.grid(column=0,row=4,columnspan=3,padx=(60,100),pady=10,sticky=tk.W)

            manual_for_open = "Opening Digital Envelope"
            manual_mes = tk.Message(manaul_open_frame, text=manual_for_open,width=600)
            manual_mes.config(fg='blue', font=('times', 16, 'italic'))
            manual_mes.grid(column=0, row=0, padx=4, pady=12, sticky=tk.W)

            cryp_txt = "Browse the folder where encrypted file and encrypted key exist :"
            cryp_label = ttk.Label(crypfile_form, text=cryp_txt)
            fontsize_13(cryp_label)
            cryp_label.grid(column=0, row=0, padx=4, pady=12,columnspan=2,sticky=tk.W)

            cryp_file_entered = ttk.Entry(crypfile_form, width=45, font=fontsize_10, textvariable=cryp_loc)
            cryp_file_entered.grid(column=0, row=1, padx=4, pady=12, ipady=7, sticky=tk.W)
            tt.create_Tooltip(cryp_file_entered,"This must be encrypted_file.txt")
            browse_button_cryp = ttk.Button(crypfile_form, text="..", command=browse_cryp, width=3)
            browse_button_cryp.grid(column=1, row=1,padx=8,pady=12,sticky=tk.W)
            tt.create_Tooltip(browse_button_cryp,"Browse button")

            # cryp_key = "Browse the encrypted key file : "
            # cryp_key = ttk.Label(crypfile_form, text=cryp_key)
            # fontsize_13(cryp_key)
            # cryp_key.grid(column=0, row=2, padx=4, pady=12, sticky=tk.W)
            #
            # cryp_key_entered = ttk.Entry(crypfile_form, width=63, font=fontsize_10, textvariable=cryp_key_loc)
            # cryp_key_entered.grid(column=0, row=3, padx=4, pady=12, ipady=7, sticky=tk.EW)
            # tt.create_Tooltip(cryp_key_entered, "This must be encrypted_key.txt")
            # browse_button_cryp = ttk.Button(crypfile_form, text="..", command=browse_cryp_key, width=3).grid(column=1, row=3,padx=8,pady=12,
            #                                                                                              sticky=tk.W)
            rsa_file = "Browse the private key of the receiver :"
            rsa_label = ttk.Label(priv_form, text=rsa_file)
            fontsize_13(rsa_label)
            rsa_label.grid(column=0, row=0, padx=4, pady=12,sticky=tk.W)

            priv_loc_entered = ttk.Entry(priv_form, width=30, font=fontsize_10, textvariable=rece_priv_loc)
            priv_loc_entered.grid(column=1, row=0, padx=4, pady=12, ipady=7, sticky=tk.EW)
            tt.create_Tooltip(priv_loc_entered,"This file must be private key of the receiver.\nThis must have the format of key length and two large numbers.Otherwise it won't work.")
            browse_button_priv = ttk.Button(priv_form, text="..", command=browse_priv_rece, width=3).grid(column=2, row=0,padx=8, sticky=tk.E)

            rsa_file = "Browse the public key of the sender :"
            rsa_label2 = ttk.Label(priv_form, text=rsa_file)
            fontsize_13(rsa_label2)
            rsa_label2.grid(column=0, row=1, padx=4, pady=12, sticky=tk.W)

            pub_loc_entered = ttk.Entry(priv_form, width=30, font=fontsize_10, textvariable=send_pub_loc)
            pub_loc_entered.grid(column=1, row=1, padx=4, pady=12, ipady=7, sticky=tk.EW)
            tt.create_Tooltip(pub_loc_entered,
                              "This file must be the public key of the receiver.\nThis must have the format of key length,two large numbers.Otherwise it won't work.")
            browse_button_pub = ttk.Button(priv_form, text="..", command=browse_pub_send, width=3).grid(column=2, row=1,padx=8,
                                                                                                     sticky=tk.E)

            sav_file_label = ttk.Label(out_form_open, text="Browse the folder to save the output files :")
            fontsize_13(sav_file_label)
            sav_file_label.grid(column=0, row=0, padx=8, pady=8, sticky=tk.W)
            sav_file_entered = ttk.Entry(out_form_open, width=25, font=fontsize_12, textvariable=sav_de_lc)
            sav_file_entered.grid(column=1, row=0, padx=8, pady=8, ipady=7, sticky=tk.EW)
            tt.create_Tooltip(sav_file_entered,"Choose the folder you want to keep the output file.")
            browse_button_pub = ttk.Button(out_form_open, text="..", command=browse_sav_rece, width=3).grid(column=2, row=0,pady=8,padx=8,
                                                                                                           sticky=tk.E)
            open_enve = ttk.Button(button_frame, text="Open an Envelope", width=10, command=_open_mes)
            open_enve.grid(column=0, row=0, ipadx=30, padx=45, ipady=15, pady=(40,20))

            menu_back = ttk.Button(button_frame, text="Back to Main Menu", width=10, command=back_menu)
            menu_back.grid(column=1, row=0, ipadx=30, padx=45, ipady=15, pady=(40,20))

            exit_button = ttk.Button(button_frame,text="Exit",width=10,command=_quit)
            exit_button.grid(column=2,row=0,ipadx=20,padx=45,ipady=15,pady=(40,20))
        elif de_count.get() > 0:
            root.withdraw()
            decryp_form.update()
            decryp_form.deiconify()

    def check_exist_file():
        if func_id.get() == 1:

            if os.path.isfile(message_loc.get()) and os.path.isfile(rece_pub_loc.get()) and os.path.isfile(send_priv_loc.get()):
                return True
            elif not os.path.isfile(message_loc.get()):
                msg.showwarning('Warning', 'The message file doesn\'t exist.')
            elif not os.path.isfile(rece_pub_loc.get()):
                msg.showwarning('Warning', 'The public key file doesn\'t exist.')
            elif not os.path.isfile(send_priv_loc.get()):
                msg.showwarning('Warning', 'The private key file doesn\'t exist.')


        elif func_id.get() == 2:

            if os.path.isfile(os.path.join(cryp_loc.get(),'encrypted_file.txt')) and os.path.isfile(os.path.join(cryp_loc.get(),'encrypted_key.txt'))  and os.path.isfile(rece_priv_loc.get()) and os.path.isfile(send_pub_loc.get()):
                return True
            elif not os.path.isfile(os.path.join(cryp_loc.get(),'encrypted_file.txt')):
                msg.showwarning('Warning','The encrypted file doesn\'t exist.')
            elif not os.path.isfile(os.path.join(cryp_loc.get(),'encrypted_key.txt')):
                msg.showwarning('Warning','The encrypted key doesn\'t exist.')
            elif not os.path.isfile(rece_priv_loc.get()):
                msg.showwarning('Warning', 'The Private key file doesn\'t exist.')
            elif not os.path.isfile(send_pub_loc.get()):
                msg.showwarning('Warning', 'The public key file doesn\'t exist.')

    def check_exist_path():
        if func_id.get() == 1:
            if os.path.isdir(sav_en_loc.get()):
                return True
            else:
                msg.showwarning('Warning', 'The Output Folder does not exist.')
        elif func_id.get() == 2:
            if os.path.isdir(sav_de_lc.get()):
                return True
            elif not os.path.isdir(sav_de_lc.get()):
                msg.showwarning('Warning', 'The Output Folder does not exist.')

    made_menu(root)
    root.iconbitmap('email.ico')
    root.mainloop()





