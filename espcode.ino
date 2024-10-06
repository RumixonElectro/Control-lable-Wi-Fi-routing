#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <EEPROM.h>

// WiFi credentials
const char* ssid = "YourSSID";  // Update with your WiFi SSID
char* password = "defaultPassword";  // Default password for initial setup

// Server parameters
ESP8266WebServer server(80);
int timerDuration = 0;
bool blink = false;
unsigned long previousMillis = 0;
const long interval = 500;  // Interval for blinking (500ms = 2 blinks per second)

void handleRoot() {
  String message = "Node MCU Server";
  server.send(200, "text/plain", message);
}

void handleSetTimer() {
  if (server.hasArg("minutes")) {
    int minutes = server.arg("minutes").toInt();
    timerDuration = minutes * 60;  //
  }
}