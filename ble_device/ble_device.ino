/*
The sketch demonstrates a simple echo BLE device
*/

#include <string.h>
#include <RFduinoBLE.h>

bool rssidisplay;
int dotcount=0;
const char * myid = "ble_device_9";   

void setup() {
   RFduinoBLE.advertisementData = "echo";
   RFduinoBLE.deviceName = myid;           // Specify BLE device name
   RFduinoBLE.begin();                            // Start the BLE stack
   Serial.begin(9600);                            // Debugging to the serial port
   Serial.print(myid); 
   Serial.println(" device restarting..."); 
}

void RFduinoBLE_onReceive(char *data, int len) { 
   data[len] = 0;  
   const char * key = "Authentication";
   if (strcmp(data, key) == 0) {
    RFduinoBLE.send("4F462FDFB18767837596", 20);
    RFduinoBLE.send("51D546333F8D", 12);

    /*
    RFduinoBLE.send("12345678912345678912",20);
    RFduinoBLE.send("12345678912345678912",20);
    RFduinoBLE.send("12345678912345678912",20);
    RFduinoBLE.send("1234",4);
    delay(1000);
    RFduinoBLE.send("123456789",9); */
   }
   /*
   Serial.print("Received: ");
   Serial.print(data);
   Serial.println("...And sending back an echo with my ID.");
   RFduinoBLE.send("Echo from ",10);
   RFduinoBLE.send(myid,strlen(myid));
   RFduinoBLE.send(": ",2);
   RFduinoBLE.send(data,len); 
   */  
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
