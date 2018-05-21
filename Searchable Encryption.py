from Crypto import Random
from Crypto.Cipher import AES
import hashlib

decrypted_dist = {}


# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

# this is the AES Librarry encrption and decryption class
class AESCipher:
    iv='';
    def __init__(self, key):
       self.bs = 32
       l= key;
       file  = open("Key_AES", "w");
       file.write(l);
     
    # this function returns hexastring        
    def bytestoHexa(self,byte):
        result = "";        
        for b in byte:
            result += format(b,"02x")+"-"
        result = result[0:-1]
        return result.upper()
    
    # this function returns bytearray
    def hextoBytes(self,hexa):
        hexa = hexa.replace("-","")
        result = [];
        result = bytearray.fromhex(hexa)
        return result
    
    #ECB Mode Encrypt    
    def encryptECB(self,plaintext):
        raw = pad(plaintext);
        if (raw is None) or (len(raw) == 0):
            raise ValueError('input text cannot be null or empty set')
        file = open("Key_AES",'r');
        k = file.read();
        key = hashlib.sha256(k.encode()).digest()
        cipher = AES.AESCipher(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(raw)
        return self.bytestoHexa(ciphertext);

    #ECB Mode decrypts     
    def decryptECB(self,cipher):
        enc = bytes(self.hextoBytes(cipher));
        file = open("Key_AES",'r');
        k = file.read();
        key = hashlib.sha256(k.encode()).digest()
        cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
        enc = unpad(cipher.decrypt(enc))        
        return enc.decode('utf-8')
    
    #CBC Mode Encrypt       
    def encryptCBC(self,plain,IV):
        p = plain# retreiving Plaintext form plain.txt
        raw = pad(p)
        iv = IV;
        file1= open("IVCBC.txt","w")
        file1.write(self.bytestoHexa(iv))
        pas = open("filesEnc.txt","r")
        k = pas.read();
        key =  hashlib.sha256(k.encode()).digest()# here we are converting the string stored 256 bytes key
        cipher = AES.new(key, AES.MODE_CBC, iv)
        c = cipher.encrypt(raw);# here encryption occurs
        return self.bytestoHexa(c);

    #CBC Mode Decrypt
    def decryptCBC(self,c):
        file1= open("IVCBC.txt","r")
        hexa= c;
        iv = bytes(self.hextoBytes(file1.read()))# here retrieved bytearray is converted  in to bytes
        enc = bytes(self.hextoBytes(hexa));
        pas = open("filesEnc.txt","r")
        k = pas.read();
        key = hashlib.sha256(k.encode()).digest()# here string key is converted 256 bit encryption key
        cipher = AES.new(key, AES.MODE_CBC, iv)        
        d = unpad(cipher.decrypt(enc)).decode('utf8');
        return d



    



# this function is mainly used to create the inverted index
def invertedIndex():
#    n = int(input("enter the number files you want to enter"));
    n=6;
    s=["" for i in range(n)];
    s = ["f1.txt","f2.txt","f3.txt","f4.txt","f5.txt","f6.txt"];
#    for i in range(n):
#        s[i] = input("enter the file name");
    
    words = [["" for i in range(1000)] for j in range(n)]
    filedict={}
    # in here we are traversing through every document and making a inverted index
    for i in range(6):
        f = open(s[i],'r');
        word = f.read().split(); 
        words[i] = list(set(word));
        for w in words[i]:
            if w not in filedict:
                filedict[w] = [i];
            else:
                l = filedict[w]
                l.append(i)
                filedict[w]=l;
    print("Files Dictionary : ",filedict);
    return filedict;


# this function is mainly used to encrypt the Keys in Inverted Index using AES ECB meathod
def enc_index(InvIndex):
    I = InvIndex;
    keys = I.keys();
    pas = open("InvIndexPass.txt","r")
    pwd = pas.read();
    enc_K = ["" for i in range(len(keys))]
    i=0;
    for key in keys:
        encrypto = AESCipher(pwd).encryptECB(key);
        enc_K[i] = encrypto;
        i=i+1;    
    return enc_K;

# this functoin is mainly used to exchange the dictionary keys with their encrypted forms from the enc_index()        
def exchangeKeys(enc_keys,keys,InvIndex):
    e = enc_keys;
    i=0;
    InvIndex11={};
    for key in keys:
        values = InvIndex[key];
        InvIndex11[e[i]] = values
        i=i+1;
    return InvIndex11;

#This is mainly used to decrypt the inverted retreived from the file "Enc_InvertedIndex.txt"
def decryptionKeys(ENC):
    gap1 = 3;# distance from enc to [ 
    l1 =  47
    start = 2;
    flag=0;
    i=2;
    pas = open("InvIndexPass.txt","r")
    pwd = pas.read();
    # this is a complex logic to retreive the inverted index from the file and decrypt it successfully
    while i<len(ENC):
        end = start+l1;
        i=start;
        i = i+l1;    
        key = ENC[start:end]
        d = AESCipher(pwd).decryptECB(key);
        i = i+gap1+1
        list1=[];
        i1 = i
        while i1<len(ENC):
            if ENC[i1] == ']':
                break;
            else:
                list1.append(int(ENC[i1])) 
                if ENC[i1+1]==']':
                    if ENC[i1+2]=='}':
                        flag=1;
                    break;
                else:
                    i1 = i1+2;
            i1=i1+1
        decrypted_dist[d] = list1;
        if flag==1:
            break;
        start = i1+5;
        
    print("Completed Decryption of the Inverted index")
    return decrypted_dist;


#this function is mainly used to encrypt all the files and upload all of them in to a file 
def files_encryption():

     s = ["f1.txt","f2.txt","f3.txt","f4.txt","f5.txt","f6.txt"];
     encrypted_file=[["" for i in range(10)] for i in range(len(s))];
     
     # here we use IV because we encrypt files using AES CBC Mode
     
     iv = Random.new().read(AES.block_size)# randomly choosing IV
     for i in range(6):
         file_name = s[i];
         file = open(file_name,"r");
         word = file.read();  
         buffer = "";
         pas = open("InvIndexPass.txt","r")
         pwd = pas.read();
         for w in word:
             if (w>='A'and w<='Z') or (w>='a'and w<'z'):
                 buffer = buffer+w;
             else:
                 enc1 = AESCipher(pwd).encryptCBC(w,iv)
                 enc = AESCipher(pwd).encryptCBC(buffer,iv)
                 encrypted_file[i].append(enc);
                 encrypted_file[i].append(enc1);
                 buffer = "";

     return encrypted_file


#This is mainly used to decrypt a single file at a time
def file_decryption_from_file(file):
    pas = open("InvIndexPass.txt","r")
    pwd = pas.read();   
    for i in file.split(","):
        if len(i) > 10 and i!=None:# here we are giving this condition to avoid some empty strings
            print("-",AESCipher(pwd).decryptCBC(i[2:len(i)-1])) # these are the files that decrypted



# this is the mainly is used to serach a word in the encrypted inverted index and retrive the indexes associated with that 
# these indexes then are used to retreive encrypted files and derypt them.
def searchFile(enc_InvIndex,search_words,filesEnc):
    pwd="password";
    enc_K = ["" for i in range(len(search_words))]
    i=0;
    #here the search are encrpyted so that they will searched in the encrypted inverted index 
    for key in search_words:
        encrypto = AESCipher(pwd).encryptECB(key);
        enc_K[i] = encrypto;
        i=i+1;    
    
    files_index=[];
    files_retrieve = [];
    index_term = 0
    for i in enc_K:
        print(i);
        try:
            files_index = enc_InvIndex[i]# here the indexes of those files are retrieved
        except:
            print("**********This word Not found**********")
            print("              ",search_words[index_term])
            print("")
            index_term +=1;
            
        print("this word is in files",files_index);
        print("***")
        for i in files_index:

            files_retrieve.append(i);
    files_index = set(files_retrieve)# here those files indexes might be repeated so they are converted in to set
    # with no repetitive file indexes
    print("indexes of the files for all Words",files_index)
    for i in files_index:# here those files with those indexs are decrpted.
        print("file:",i)
        print(file_decryption_from_file(filesEnc[i]))


# first we are creating inverted index
InvIndex = invertedIndex();
print("Inverted Index",InvIndex)
print("\n\n\n\n\n")

# Encrypting the Inverted index 
enc_keys = list(enc_index(InvIndex));
enc_InvIndex = exchangeKeys(enc_keys,InvIndex.keys(),InvIndex)
print("Encrypted Inverted Index",enc_InvIndex)
print("\n\n\n\n\n")

#this Encrypted inverted index is copied in to a file
file=open("Enc_InvertedIndex.txt","w");
file.write(str(enc_InvIndex));

#Reading the Encrypted Inverted index from file
file=open("Enc_InvertedIndex.txt","r");
ENC = file.read();
decrypted_dist = decryptionKeys(ENC)
print("decrypted inverted Index : ",decrypted_dist);
print("\n\n\n\n\n")


# taking the search Keyswords
search_keywords=[];
t = True
while t:
    try:
        n_words = int(input("Enter the number of words you want to search in the index"));
        t= False;
    except:
        print("")
        print("**Enter number of word you want to search**")
        
for i in range(n_words):
    word = input("Enter the word");
    search_keywords.append(word);                                                                                                

# now the files are Encrypted. These are the template files to show the working of this project
enc_files = files_encryption()
encrypted_collection_file = open("Encrypted_files.txt","w")
encrypted_collection_file.write(str(enc_files));
encrypted_collection_file = open("Encrypted_files.txt","r")
files  = encrypted_collection_file.read()
s = "";
l  ="";
flag=1;
filesEnc = []


# here we are dividing the text in to different files
for i in files:
    if flag==1 and i!=']' and i!='[':
        l = l+i
    if i =="[":
        flag=1;
    if i=="]":
        filesEnc.append(l)
        l="";
        flag=0;   

# here the search is executed this will return the files these both words are present in
searchFile(enc_InvIndex,search_keywords,filesEnc)