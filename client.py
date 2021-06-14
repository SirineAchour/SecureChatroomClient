import base64
import sys, socket, select
from Crypto.Cipher import AES
import os
import hashlib
import signal
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import NoEncryption
import time
import getpass
from cryptography.hazmat.primitives.asymmetric import padding
import platform

BUFFER_SIZE = 8192
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
os.system("clear")

def sigint_handler(signum, frame):
    print('\n User disconnected !!')
    print("[info] shutting down Chat \n\n")
    sys.exit()  
    

signal.signal(signal.SIGINT, sigint_handler)

def create_csr(country , state , locality , org , cn , key) :     
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])).add_extension(
        x509.BasicConstraints(ca = False , path_length = None ) ,
        critical=True,
    # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())
    # Write our CSR out to disk.
    with open("clientcsr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

def genkey() :      
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write our key to disk for safe keeping
    with open("clientkey.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm= NoEncryption(),
        ))
    return key 

def encrypt(public_key,msg):
    ciphertext = public_key.encrypt(
    msg,
    padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
    )
    )
    return ciphertext

def decrypt (public_key,msg):
    data = public_key.decrypt(
    msg,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )
    return data

def send_file(pref , file) :
    print("pref : "+str(pref))
    print("file : "+str(file))
    f = open(file, 'rb') 
    l = f.read(BUFFER_SIZE)
    tmp = pref + l.decode("utf-8")
    s.sendall(tmp.encode('utf-8'))
    s.recv(1)
    f.close()

def send_msg(msg) : 
    print("sending : ")
    print(str(msg))
    data = str(msg)
    s.sendall(data.encode('utf-8'))
    print("waiting for recv 1")
    s.recv(1)
    print("received 1")


def recv_msg( ) : 
    data = s.recv(8192)
    s.sendall('1'.encode('utf-8'))
    print("received this : "+str(data.decode("utf-8")))
    return data.decode("utf-8")


def rcv_file(file) :
    filename=str(file)
    with open(filename,'wb') as f : 
        data = s.recv(BUFFER_SIZE)
        f.write(data)
        f.close()
    s.sendall('1'.encode('utf-8'))


def register(ind,msg,key) :
    login = input('login : ')
    password = getpass.getpass()
    email = input('email : ')
    carte = input('NCarte: ')

    create_csr(u"at",u"at",u"at",u"at",u"at",key)
    print("ind : "+str(ind))
    print("msg : "+str(msg))
    send_file(str(ind)+msg , 'clientcsr.pem') 
    rcv_file("certificate.pem")
    rcv_file("ca.pem")  
    print('registration complete') 
    send_msg(login)
    send_msg(password)
    send_msg(email)
    send_msg(carte)
    print("GONNA WAIT FOR ANSWER")
    answer = recv_msg()
    print("got answer")
    print(answer)
    print("done with registration")


def recv_available_clients():
    msg =  recv_msg()
    while msg != 'abc' :
      print(msg)
      msg = recv_msg()
      

def auth(ind) : 
    send_msg(str(ind) + 'aut')
    print('time to authenticate : \n')
    login = input('login : ')
    password = getpass.getpass()
    send_msg(login)
    send_msg(password)
    answer = recv_msg()
    if answer == 'done' :
        print('authentification complete' )
        print('\navailable people to chat with : \n')
        recv_available_clients()
    else :
        print('error , bad credentials')
        auth(ind)


def chat_client():
    if(len(sys.argv) < 5) :
        print('Run : python client.py <hostname|ip_address> <port> <password> <nick_name>')
        sys.exit()
    key = genkey()
    host = sys.argv[1]
    port = int(sys.argv[2]) 
    uname = sys.argv[4]
    ind = 0 
    newuser = False 
    #s.settimeout()
    reciever = 'none'

    try :
        s.connect((host, port))
        print("connected to server now waiting for msg")
        ind = recv_msg()

        print(str(ind) )
    except :
        print("\033[91m"+'Unable to connect, Server is unavailable'+"\033[0m")
        sys.exit()

    print("Connected to the chat server. You can start sending messages.")
    

    if (not os.path.isfile('certificate.pem') ) : 
        print('this is a new user , you should register')
        register(ind,'csr',key)
    auth(ind)
    pem_ca_cert = open('ca.pem','rb').read()
    
    ca_cert = x509.load_pem_x509_certificate(pem_ca_cert, default_backend())
    ca_key =  ca_cert.public_key()    


    pem_ca_key = open('clientkey.pem' , 'rb').read()
    my_key = serialization.load_pem_private_key(pem_ca_key, password = None,backend = default_backend()) 


    sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()
    while 1:
        socket_list = [sys.stdin, s]
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            if sock == s:
                data = recv_msg()
                if not data :
                    print("\033[91m"+"\nServer shutdown !!"+"\033[0m")
                    sys.exit()
                elif data[:7] == 'nouveau':
                    sys.stdout.write(data)
                else : 
                    data = decrypt(my_key,data)
                    sys.stdout.write(data)
                    sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()

            else :
                msg = sys.stdin.readline()
                if reciever == 'none' : 
                    reciever = input('choose reciever : ')
                send_msg(str(ind)+'msg')
                send_msg(reciever)
                msg = encrypt(ca_key,msg)
                send_msg(msg)
                
                sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()



def users(connected):
    pass

def signup(ind,msg,key,username,password) :
    try:
        create_csr(u"at",u"at",u"at",u"at",u"at",key)
        send_file(str(ind)+msg , 'clientcsr.pem') 
        rcv_file("certificate.pem")
        rcv_file("ca.pem")  
        send_msg(username)
        send_msg(password)
        answer = recv_msg()
        print("Sign up succeded!")
        return True
    except:
        print("Something went wrong :( try again ?")
        return False

def login(ind, username, password):
    print("*in login")
    try:
        send_msg(str(ind) + 'aut')
        send_msg(username)
        send_msg(password)
        answer = recv_msg()
        if answer == 'done' :
            print('Login succeeded!' )
            #print('\navailable people to chat with : \n')
            #recv_available_clients()
            input()
            return True
        else :
            print("Busted! You're not really "+str(username)+".. Go away imposter!")
            input()
            return False
    except:
            print("Something went wrong :( try again ?")
            return False

def clear():
    if os_name == "Windows":
        os.system('cls')
        return
    if os_name == "Linux":
        os.system('clear')
        return

def logged_in_menu(username):
    logged_in = True
    while logged_in:
        clear()
        print("Hi " + str(username) + "!")
        print("1- Users")
        print("2- Messages")
        print("3- Log out")
        print("4- Delete account")

        option = input()
        clear()
        stay_in_submenu = True
        if option == "1":
            while stay_in_submenu:
                print("1- Connected users")
                print("2- All users")
                print("3- Return")
                submenu_option = input()
                clear()
                if submenu_option == "1":
                    print("CONNECTED USERS:")
                    users(True)
                    input()
                    clear()
                elif submenu_option == "2":
                    print("ALL USERS:")
                    users(False)
                    input()
                    clear()
                elif submenu_option == "3":
                    stay_in_submenu = False
                else:
                    stay_in_submenu = True
        elif option == "2":
            while stay_in_submenu:
                print("1- New message")
                print("2- All messages")
                print("3- Return")
                submenu_option = input()
                clear()
                if submenu_option == "1":
                    print("NEW MESSAGE:")
                    target = input("Target : ")

                    if actions.check_if_user_in_list_of_users(target):
                        msgs = []
                        msg = input("Message : ")
                        while len(msg) != 0:
                            msgs.append(msg)
                            msg = input("Message : ")
                        for msg in msgs:
                            actions.send_new_message(target, msg)
                        print("Messages sent!")
                    else:
                        print("Boohoo user doesn't exist")
                    input()
                    clear()
                elif submenu_option == "2":
                    print("ALL MESSAGES:")
                    messages = []
                    messages = actions.messages(username)
                    i = 1
                    for message in messages:
                        print(str(i) + ") " + message['sender'] + ": " + message['msg'])
                        i = i + 1
                    i = input()
                    clear()

                    convo = []
                    convo = actions.messages_of_user(username, messages[int(i) - 1]['sender'])
                    for line in convo:
                        print("(" + line["date"] + ") " + line['sender'] + ": " + line['msg'])
                    # start thread that sends msgs
                    send_msgs_thread = threading.Thread(target=actions.send_message,
                                                        args=(username, messages[int(i) - 1]['sender'],))
                    send_msgs_thread.start()

                    # _thread.start_new_thread(actions.send_message, (username, messages[int(i) - 1]['sender'], ))

                    # start thread that receives msgs
                    receive_msgs_thread = threading.Thread(target=actions.receive_message,
                                                           args=(username, messages[int(i) - 1]['sender'],))
                    receive_msgs_thread.start()
                    send_msgs_thread.join()
                    receive_msgs_thread.join()
                    # _thread.start_new_thread(actions.receive_message, (username, messages[int(i) - 1]['sender'],))

                    input()
                    clear()
                elif submenu_option == "3":
                    stay_in_submenu = False
                else:
                    stay_in_submenu = True

        elif option == "3":
            while stay_in_submenu:
                print("Are you sure you want to log out ?")
                print("1- Yes")
                print("3- No")
        elif option == "4":
            while stay_in_submenu:
                print("Are you sure you want to delete your account ? "
                      "Once you do, all messages will be deleted and this account can never be recovered")
                print("1- Yes")
                print("3- No")
        else:
            pass

def validate_username(username, existing):
    if " " in username:
        print("Can't have spaces in a username :( try another one")
        return False
    # check unicity
    send_msg(str(ind) + 'srh')
    send_msg(username)
    m = recv_msg()
    if existing and m == '1':
        return True
    elif not existing and m == '0':
        return True
    else:
        return False

def validate_password(password):
    if len(str(password)) == 0:
        return False
    return True

def main_menu(ind,key):
    exit = False
    print("Welcome welcome!")
    while not exit:
        print("1- Sign up")
        print("2- Login")
        print("3- Exit")

        choice = input()
        clear()
        if choice == "1":
            print("SIGN UP:\nPlease provide a valid and unique username :")
            username = input()
            while not validate_username(username, False):
                username = input()

            print("Now provide a password (make sure to use symbols, numbers and letters and make it long):")
            password = getpass.getpass()
            while not validate_password(password):
                print("Huh... Is that really the password you want ? I don't think so. Try again")
                #password = input()
                password = getpass.getpass()
            if signup(ind,'csr',key, username, password):
                #logged_in_menu(username)
                print("Now go login")
                input()
                clear()

        elif choice == "2":
            print("LOGIN:\nUsername ?")
            username = input()
            while not validate_username(username, True):
                username = input()

            print("Password ?")
            password = getpass.getpass()
            if not validate_password(password):
                print("That can't really be your password.. try again")
            else:
                print("Are you really " + str(username) + " ? Checking...")
                if login(ind, username, password):
                    logged_in_menu(username)

        elif choice == "3":
            exit = True
        else:
            pass


if __name__ == "__main__":
    os_name = platform.system()
    if(len(sys.argv) < 3) :
        print('Run : python client.py <hostname|ip_address> <port>')
        sys.exit()
    key = genkey()
    host = sys.argv[1]
    port = int(sys.argv[2]) 
    #uname = sys.argv[4]
    ind = 0 
    newuser = False 
    #s.settimeout()
    reciever = 'none'

    try :
        s.connect((host, port))
        ind = recv_msg()

        print(str(ind) )
    except :
        print("\033[91m"+'Unable to connect, Server is unavailable'+"\033[0m")
        sys.exit()

    print("Connected to the chat server. You can start sending messages.")
    sys.exit(main_menu(ind,key))

