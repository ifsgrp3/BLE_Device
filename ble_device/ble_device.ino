#include <RFduinoBLE.h>
#include <string.h>
#include <Crypto.h>
#include <AES.h>
#include <string.h>

AES128 aes128;
bool rssidisplay;
int dotcount=0;
const char * myid = "ble_device_9";

struct credential_set {
    byte key[32];
    byte serial_num[16];
};

static credential_set const credentials = {
    .key = {0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x33, 0x34, 0x34, 0x34, 0x34},
    .serial_num = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36}
};
/*
struct credential_set {
    byte key[32];
    byte serial_num[64];
};

static credential_set const credentials = {
    .key = {0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x33, 0x34, 0x34, 0x34, 0x34},
    .serial_num = {0x35, 0x77, 0x34, 0x6c, 0x6a, 0x39, 0x6e, 0x65, 0x6b, 0x30, 0x64, 0x70, 0x7a, 0x31, 0x6f, 0x37, 0x33, 0x61, 0x73, 0x73, 0x67, 0x73, 0x78, 0x34, 0x70, 0x67, 0x36, 0x70, 0x6a, 0x37, 0x33, 0x7a, 0x74, 0x6a, 0x72, 0x38, 0x77, 0x7a, 0x35, 0x62, 0x6b, 0x7a, 0x6b, 0x33, 0x71, 0x74, 0x63, 0x6a, 0x35, 0x6d, 0x69, 0x65, 0x78, 0x68, 0x71, 0x61, 0x6a, 0x6b, 0x61, 0x37, 0x72, 0x65, 0x34, 0x63}
}; */

void byte_array_to_string(byte array[], unsigned int len, char result[]) {
    for (unsigned int i = 0; i < len; i++) {
    byte nib_1 = (array[i] >> 4) & 0x0F;
    byte nib_2 = (array[i] >> 0) & 0x0F;
    result[i*2+0] = nib_1  < 0xA ? '0' + nib_1  : 'A' + nib_1  - 0xA;
    result[i*2+1] = nib_2  < 0xA ? '0' + nib_2  : 'A' + nib_2  - 0xA;
    }
    result[len*2] = '\0';
}

void substring(char str[], char new_str[], int pos, int len) {
    int i = 0;
    while (i < len) {
      new_str[i] = str[pos+i-1];
      i++;
    }
    new_str[i] = '\0';
}

void print_Hex(uint8_t num) {
    char hex_Car[2];
    sprintf(hex_Car, "%02X", num);
    Serial.print(hex_Car);
}

void aes_encrypt(BlockCipher *cipher, const struct credential_set *credentials, byte ciphertext[16]) {
    crypto_feed_watchdog();
    cipher->setKey(credentials->key, cipher->keySize());
    cipher->encryptBlock(ciphertext, credentials->serial_num);
    /*
    char str[65];
    memcpy(str, ciphertext, 64);
    str[64] = 0;
    for(int i=0; i<64; i++){
    print_Hex(str[i]);
    } */
}

void setup() {
    RFduinoBLE.advertisementData = "echo";
    RFduinoBLE.deviceName = myid;           // Specify BLE device name
    RFduinoBLE.begin();                            // Start the BLE stack
    Serial.begin(9600);                            // Debugging to the serial port
    Serial.print(myid); 
    Serial.println(" device restarting..."); 
}

void RFduinoBLE_onReceive(char *data, int len) {
    const char * authentication_code = "Authentication";
    data[len] = 0;  
    char ciphertext[128] = "";
    char packet_1[20];
    char packet_2[12];
    byte ciphertext_array[16];

    Serial.println("\nAuthentication code received");

    if(strcmp(data, authentication_code) == 0) {
      Serial.println("Authentication code success");
      Serial.println("Encrypting serial number");
      aes_encrypt(&aes128, &credentials, ciphertext_array);
      byte_array_to_string(ciphertext_array, 16, ciphertext);
      substring(ciphertext, packet_1, 1, 20);
      substring(ciphertext, packet_2, 21, 12);
      Serial.println("Transmitting encrypted serial number");
      RFduinoBLE.send(packet_1, 20);
      RFduinoBLE.send(packet_2, 12);
    } else {
      Serial.println("Authentication code failed!");
    } 
}

void loop() {
    RFduino_ULPDelay( SECONDS(0.5) );                // Ultra Low Power delay for 0.5 second
    dotcount++;
    if (dotcount<40) {
      Serial.print("."); 
    } else {
      Serial.println();
      dotcount=0;
    }
}





/*
   testCipher(&aes128, &testVectorAES128);
   perfCipher(&aes128, &testVectorAES128);
   delay(10000); */
/*
   RFduinoBLE.send("4F462FDFB18767837596", 20);
   RFduinoBLE.send("51D546333F8D", 12); 
   
   RFduinoBLE.send("12345678912345678912",20);
   RFduinoBLE.send("12345678912345678912",20);
   RFduinoBLE.send("12345678912345678912",20);
   RFduinoBLE.send("1234",4);
   delay(1000);
   RFduinoBLE.send("123456789",9);  
    
   Serial.print("Received: ");
   Serial.print(data);
   Serial.println("...And sending back an echo with my ID.");
   RFduinoBLE.send("Echo from ",10);
   RFduinoBLE.send(myid,strlen(myid));
   RFduinoBLE.send(": ",2);
   RFduinoBLE.send(data,len); */  

/*
   String msg = "1234567890123456";
   String key_str="1111222233334444";
   String iv_str="1111222233334444";
   do_encrypt(msg, key_str, iv_str);

   delay(5000); */

/*
#include <AES.h>
#include <base64.h>
#include <AESLib.h>
#incldude <AES_config.h>
#include <pgmspace.h> 

AES aes;
byte cipher[1000];
char b64[1000];
byte *key = (unsigned char*)"1111222233334444";
byte plain[] = "1234567890123456"; */

/*
void do_encrypt(String msg, String key_str, String iv_str) {
  byte iv[16];
  memcpy(iv,(byte *) iv_str.c_str(), 16);

  int blen = base64_encode(b64,(char *)msg.c_str(),msg.length());

  aes.calc_size_n_pad(blen);

  int len = aes.get_size();
  byte plain_P[len];
  for(int i=0;i<blen;i++) plain_p[i]=b64[i];
  for(int i=blen;i<len;i++) plain_P[i]='\0';

  int blocks = len/16
  aes.set_key ((byte *)key_str.c_str(), 16);
  aes.cbc_encrypt (plain_p, cipher, blocks, iv);

  Serial.println("Encrypted Data output: " + String((char*)b64));
} */

/*
struct TestVector {
  const char *name;
  byte key[32];
  byte plaintext[16];
  byte ciphertext[16];
};

static TestVector const testVectorAES128 = {
  .name = "AES-128-ECB",
  .key = {0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x33, 0x34, 0x34, 0x34, 0x34},
  .plaintext = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36},
  .ciphertext = {0x4F, 0x46, 0x2F, 0xDF, 0xB1, 0x87, 0x67, 0x83, 0x75, 0x96, 0x51, 0xD5, 0x46, 0x33, 0x3F, 0x8D}
}; */

/*
void testCipher(BlockCipher *cipher, const struct TestVector *test)
{
    crypto_feed_watchdog();
    Serial.print(test->name);
    Serial.print(" Encryption ... ");
    cipher->setKey(test->key, cipher->keySize());
    cipher->encryptBlock(buffer, test->plaintext);
    char str[17];
    memcpy(str, buffer, 16);
    str[16] = 0;
    for(int i=0; i<16; i++){
    printHex(str[i]);
    }
    if (memcmp(buffer, test->ciphertext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");

    Serial.print(test->name);
    Serial.print(" Decryption ... ");
    cipher->decryptBlock(buffer, test->ciphertext);
    if (memcmp(buffer, test->plaintext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");
} */

/*
void perfCipher(BlockCipher *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    crypto_feed_watchdog();

    Serial.print(test->name);
    Serial.print(" Set Key ... ");
    start = micros();
    for (count = 0; count < 10000; ++count) {
        cipher->setKey(test->key, cipher->keySize());
    }
    elapsed = micros() - start;
    Serial.print(elapsed / 10000.0);
    Serial.print("us per operation, ");
    Serial.print((10000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");

    Serial.print(test->name);
    Serial.print(" Encrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->encryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    Serial.print(test->name);
    Serial.print(" Decrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->decryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    Serial.println();
} */

/*
bool testCipher_N(Cipher *cipher, const struct TestVector *test, size_t inc)
{
    byte output[MAX_CIPHERTEXT_SIZE];
    size_t posn, len;

    cipher->clear();
    if (!cipher->setKey(test->key, cipher->keySize())) {
        Serial.print("setKey ");
        return false;
    }
    if (!cipher->setIV(test->iv, cipher->ivSize())) {
        Serial.print("setIV ");
        return false;
    }

    memset(output, 0xBA, sizeof(output));

    for (posn = 0; posn < test->size; posn += inc) {
        len = test->size - posn;
        if (len > inc)
            len = inc;
        cipher->encrypt(output + posn, test->plaintext + posn, len);
    }

    if (memcmp(output, test->ciphertext, test->size) != 0) {
        Serial.print(output[0], HEX);
        Serial.print("->");
        Serial.print(test->ciphertext[0], HEX);
        return false;
    }

    cipher->setKey(test->key, cipher->keySize());
    cipher->setIV(test->iv, cipher->ivSize());

    for (posn = 0; posn < test->size; posn += inc) {
        len = test->size - posn;
        if (len > inc)
            len = inc;
        cipher->decrypt(output + posn, test->ciphertext + posn, len);
    }

    if (memcmp(output, test->plaintext, test->size) != 0)
        return false;

    return true;
} */

/*
void RFduinoBLE_onReceive(char *data, int len) {
    const char * authentication_code = "Authentication";
    data[len] = 0;  
    char ciphertext[128] = "";
    char packet_1[20];
    char packet_2[12];
    
    char packet_1[20];
    char packet_2[20];
    char packet_3[20];
    char packet_4[4];
    char packet_5[20];
    char packet_6[20];
    char packet_7[20];
    char packet_8[4];
    //byte ciphertext_array[16];
    byte ciphertext_array[64];

    Serial.println("\nAuthentication code received");
    
    if(strcmp(data, authentication_code) == 0) {
      Serial.println("Authentication code success");
      Serial.println("Encrypting serial number");
      aes_encrypt(&aes128, &credentials, ciphertext_array);
      byte_array_to_string(ciphertext_array, 64, ciphertext);
      substring(ciphertext, packet_1, 1, 20);
      substring(ciphertext, packet_2, 21, 20);
      substring(ciphertext, packet_3, 41, 20);
      substring(ciphertext, packet_4, 61, 4);
      substring(ciphertext, packet_5, 65, 20);
      substring(ciphertext, packet_6, 85, 20);
      substring(ciphertext, packet_7, 105, 20);
      substring(ciphertext, packet_8, 125, 4);
      Serial.println("Transmitting encrypted serial number");
      RFduinoBLE.send(packet_1, 20);
      RFduinoBLE.send(packet_2, 20);
      RFduinoBLE.send(packet_3, 20);
      RFduinoBLE.send(packet_4, 4);
      delay(10000);
      RFduinoBLE.send(packet_5, 20);
      RFduinoBLE.send(packet_6, 20);
      RFduinoBLE.send(packet_7, 20);
      RFduinoBLE.send(packet_8, 4);
    } else {
      Serial.println("Authentication code failed!");
    }
   
    if(strcmp(data, authentication_code) == 0) {
      Serial.println("Authentication code success");
      Serial.println("Encrypting serial number");
      aes_encrypt(&aes128, &credentials, ciphertext_array);
      byte_array_to_string(ciphertext_array, 16, ciphertext);
      substring(ciphertext, packet_1, 1, 20);
      substring(ciphertext, packet_2, 21, 12);
      Serial.println("Transmitting encrypted serial number");
      RFduinoBLE.send(packet_1, 20);
      RFduinoBLE.send(packet_2, 12);
    } else {
      Serial.println("Authentication code failed!");
    } 
} */
