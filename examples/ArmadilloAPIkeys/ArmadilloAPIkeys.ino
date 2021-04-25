#include <ArmadilloHTTP.h> 

ArmadilloHTTP aClient;

void ArmadilloError(int e,int info){
  switch(e){
//
//   From Aardvark, deriving from TCP server handling 
//
    case VARK_TCP_DISCONNECTED:
        Serial.printf("ERROR: NOT CONNECTED info=%d\n",info);
        break;
    case VARK_TCP_UNHANDLED:
        Serial.printf("ERROR: UNHANDLED TCP ERROR info=%d\n",info);
        break;
    case VARK_TLS_BAD_FINGERPRINT:
        Serial.printf("ERROR: TLS_BAD_FINGERPRINT info=%d\n",info);
        break;
    case VARK_TLS_NO_FINGERPRINT:
        Serial.printf("WARNING: NO FINGERPRINT, running insecure\n");
        break;
    case VARK_TLS_NO_SSL:
        Serial.printf("ERROR: secure https:// requested, NO SSL COMPILED-IN: READ DOCS!\n");
        break;
    case VARK_TLS_UNWANTED_FINGERPRINT:
        Serial.printf("WARNING: FINGERPRINT provided, insecure http:// given\n");
        break;
    case VARK_NO_SERVER_DETAILS: //  
        Serial.printf("ERROR:NO_SERVER_DETAILS info=%02x\n",info);
        break;
    case VARK_INPUT_TOO_BIG: //  
        Serial.printf("ERROR: RX msg(%d) that would 'break the bank'\n",info);
        break;
//
//   From Armadillo itself, deriving from the HTTP protocol 
//
    case ARMA_ERROR_BUSY:
        Serial.printf("ARMA:request already in-flight\n");
        break;
    case ARMA_ERROR_HTTP:
        Serial.printf("ARMA:HTTP_ERROR %d\n",info);
        break;
    case ARMA_ERROR_TOO_BIG:
        Serial.printf("ARMA:RX DATA TOO BIG %d\n",info);
        break;
    case ARMA_ERROR_TCP_UNHANDLED:
        Serial.printf("ARMA:UNHANDLED TCP ERROR %d\n",info);
        break;
    case ARMA_ERROR_VERB_PROHIBITED:
        Serial.printf("ARMA:VERB NOT ALLOWED\n");
        break;
    case ARMA_ERROR_CHUNKED:
        Serial.printf("ARMA: Cannot handle xfer chunked (yet)\n");
        break;
    default:
        Serial.printf("UNKNOWN ERROR: %d extra info %d\n",e,info);
        break;
    }
}
//
#define WIFI_SSID "XXXXXXXX"
#define WIFI_PASSWORD "XXXXXXXX"

// if you provide a valid certificate fingerprinting when connecting, it will be checked and fail on no match
// if you do not provide one, Armadillo will continue insecurely with a warning
// this one is MY local mosquitto server... it ain't gonna work, so either don't use one, or set your own!!!
//const uint8_t cert[20] = { 0x9a, 0xf1, 0x39, 0x79,0x95,0x26,0x78,0x61,0xad,0x1d,0xb1,0xa5,0x97,0xba,0x65,0x8c,0x20,0x5a,0x9c,0xfa };
//#define ARMADILLO_URL "https://robot.local:8883"

//#define ARMADILLO_URL "http://robot.local:1883"
//const uint8_t* cert=nullptr;

#define ARMADILLO_URL "https://restcountries-v1.p.rapidapi.com/name/kazakhstan"

void responseHandler(ARMA_HTTP_REPLY r){
  Serial.printf("HTTP Response Code: %d\n",r.httpResponseCode);
  Serial.printf("Response Headers:\n");
  for(auto const h:r.responseHeaders) Serial.printf("%s=%s\n",h.first.data(),h.second.data());
  Serial.printf("\nRaw Data\n");
  dumphex(r.data,r.length);
  Serial.printf("\nAs a std::string - BE CAREFUL, IT MAY NOT BE A STRING!!!\n%s\n",r.asStdstring().data()); // Data may NOT be a string -> crash!!!
  // see pmbtools docs for meaning of "simple json" and ONLY do this if you KNOW 100% response fits that pattern
  //Serial.printf("\nAs simple JSON - BE CAREFUL, complex will break it...AND it may not be JSON!!!\n");
  //for(auto const& j:r.asSimpleJson()) Serial.printf("%s=%s\n",j.first.data(),j.second.data());
}

void setup() {
  Serial.begin(115200);

  WiFi.begin("XXXXXXXX","XXXXXXXX");
  while(WiFi.status()!=WL_CONNECTED){
    Serial.printf(".");
    delay(1000);
  }
  Serial.printf("WIFI CONNECTED IP=%s\n",WiFi.localIP().toString().c_str());

  aClient.onHTTPerror(ArmadilloError);

  aClient.addRequestHeader("x-rapidapi-key","< get your own key!!! >");
  aClient.addRequestHeader("x-rapidapi-host","restcountries-v1.p.rapidapi.com");

  aClient.GET(ARMADILLO_URL,responseHandler);
}

void loop() {}