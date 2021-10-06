#include <RFduinoBLE.h>
#include <string.h>
#include <Crypto.h>
#include <AES.h>
#include <string.h>

bool rssidisplay;
int dotcount=0;
const char * myid = "ble_device_9";

struct TestVector {
  const char *name;
  byte key[32];
  byte plaintext[16];
  byte ciphertext[16];
};

/*
static TestVector const testVectorAES128 = {
  .name = "AES-128-ECB",
  .key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
  .plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
  .ciphertext = {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A}
}; */

void array_to_string(byte array[], unsigned int len, char buffer[])
{
    for (unsigned int i = 0; i < len; i++)
    {
        byte nib1 = (array[i] >> 4) & 0x0F;
        byte nib2 = (array[i] >> 0) & 0x0F;
        buffer[i*2+0] = nib1  < 0xA ? '0' + nib1  : 'A' + nib1  - 0xA;
        buffer[i*2+1] = nib2  < 0xA ? '0' + nib2  : 'A' + nib2  - 0xA;
    }
    buffer[len*2] = '\0';
}

static TestVector const testVectorAES128 = {
  .name = "AES-128-ECB",
  .key = {0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x33, 0x34, 0x34, 0x34, 0x34},
  .plaintext = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36},
  .ciphertext = {0x4F, 0x46, 0x2F, 0xDF, 0xB1, 0x87, 0x67, 0x83, 0x75, 0x96, 0x51, 0xD5, 0x46, 0x33, 0x3F, 0x8D}
};

AES128 aes128;
byte buffer[16];

void printHex(uint8_t num) {
  char hexCar[2];

  sprintf(hexCar, "%02X", num);
  Serial.print(hexCar);
}

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
}

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
}
void setup() {
   RFduinoBLE.advertisementData = "echo";
   RFduinoBLE.deviceName = myid;           // Specify BLE device name
   RFduinoBLE.begin();                            // Start the BLE stack
   Serial.begin(9600);                            // Debugging to the serial port
   Serial.print(myid); 
   Serial.println(" device restarting..."); 
}

void substring(char str[], char new_str[], int pos, int len) {
   int i = 0;
   while (i < len) {
      new_str[i] = str[pos+i-1];
      i++;
   }
   new_str[i] = '\0';
}

void RFduinoBLE_onReceive(char *data, int len) { 
   data[len] = 0;  
   char str[] = "";
   char packet_1[20];
   char packet_2[12];
   byte array[16] = {0x4F, 0x46, 0x2F, 0xDF, 0xB1, 0x87, 0x67, 0x83, 0x75, 0x96, 0x51, 0xD5, 0x46, 0x33, 0x3F, 0x8D};
   array_to_string(array, 16, str);
   substring(str, packet_1, 1, 20);
   substring(str, packet_2, 21, 12);
   Serial.print("packet1");
   for (int i=0; i < 20; i++) {
    Serial.print(packet_1[i]);
   }
   
   const char * key = "Authentication";
   if (strcmp(data, key) == 0) {
    RFduinoBLE.send(packet_1, 20);
    RFduinoBLE.send(packet_2, 12);
    /*
    RFduinoBLE.send("4F462FDFB18767837596", 20);
    RFduinoBLE.send("51D546333F8D", 12); */
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
   testCipher(&aes128, &testVectorAES128);
   perfCipher(&aes128, &testVectorAES128);
   delay(10000);
}
/*
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
   RFduinoBLE.send(data,len); 
*/  

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
