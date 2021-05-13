#pragma once

#include<dillo_config.h>

#include<AardvarkTCP.h>
#include<unordered_set>

#include<mbx.h>

constexpr const char* contentTypeTag() { return "CONTENT-TYPE"; }
constexpr const char* contentLengthTag() { return "CONTENT-LENGTH"; }

extern void dumphex(const uint8_t*,size_t);

#if ARMA_DEBUG
    template<int I, typename... Args>
    void ARMA_PRINT(const char* fmt, Args... args) {
        if (ARMA_DEBUG >= I) Serial.printf(std::string(std::string("ARMA:%d: ")+fmt).c_str(),I,args...);
    }
    #define ARMA_PRINT1(...) ARMA_PRINT<1>(__VA_ARGS__)
    #define ARMA_PRINT2(...) ARMA_PRINT<2>(__VA_ARGS__)
    #define ARMA_PRINT3(...) ARMA_PRINT<3>(__VA_ARGS__)
    #define ARMA_PRINT4(...) ARMA_PRINT<4>(__VA_ARGS__)

    template<int I>
    void ARMA_dump(const uint8_t* p, size_t len) { if (ARMA_DEBUG >= I) dumphex(p,len); }
    #define ARMA_DUMP3(p,l) ARMA_dump<3>((p),l)
    #define ARMA_DUMP4(p,l) ARMA_dump<4>((p),l)
#else
    #define ARMA_PRINT1(...)
    #define ARMA_PRINT2(...)
    #define ARMA_PRINT3(...)
    #define ARMA_PRINT4(...)

    #define ARMA_DUMP3(...)
    #define ARMA_DUMP4(...)
#endif

enum {
    ARMA_ERROR_BUSY = VARK_MAX_ERROR,
    ARMA_ERROR_HTTP,
    ARMA_ERROR_TOO_BIG,
    ARMA_ERROR_TCP_UNHANDLED,
    ARMA_ERROR_VERB_PROHIBITED,
    ARMA_ERROR_CHUNKED
};

enum {
    ARMA_PHASE_PREFLIGHT,
    ARMA_PHASE_MEASURE,
    ARMA_PHASE_EXECUTE
};

using ARMA_METHODS      = std::unordered_set<std::string>;

struct ArmadilloHTTPresponse {
    uint32_t        httpResponseCode;
    VARK_NVP_MAP    responseHeaders;
    ARMA_METHODS    allowedMethods;
    const uint8_t*  data;
    size_t          length;

    std::string     asJsonstring(){ return (responseHeaders[contentTypeTag()].find("json")!=std::string::npos) ? string((const char*) data, length):""; }
    VARK_NVP_MAP    asSimpleJson(){ return json2nvp(asJsonstring()); }
    std::string     asStdstring(){ return string((const char*) data, length); }
};

using ARMA_HTTP_REPLY  = struct ArmadilloHTTPresponse;
using ARMA_INT_MAP      = std::map<uint32_t,std::string>;
using ARMA_FN_HTTP      = std::function<void(ARMA_HTTP_REPLY)>;
using ARMA_CHUNKS       = std::vector<mbx>;

class ArmadilloHTTP: public AardvarkTCP {
        std::string     _bodydata;
        size_t          _sigmaChunx=0;
        uint32_t        _phase=0;
        bool            _inflight=false;
        
        ARMA_INT_MAP _phaseVerb={
            {ARMA_PHASE_PREFLIGHT,"OPTIONS"},
            {ARMA_PHASE_MEASURE,"HEAD"},
            {ARMA_PHASE_EXECUTE,"GET"}
        };

        ARMA_HTTP_REPLY _response;
        ARMA_CHUNKS     _chunks;
        ARMA_FN_HTTP    _userfn;
        void            _appendHeaders(std::string* p);
        void            _chunkItUp(uint8_t* pMsg,const uint8_t* d,size_t s);
        bool            _compareHeader(const std::string& h,const std::string& v);
        void            _error(int e,int i=0){ _causeError(e,i); }
        size_t          _getContentLength();
        void            _getMethods(const std::string& hdr);
        size_t          _hex2uint(const uint8_t *str);
        void            _prepare(uint32_t phase,const std::string& _verb,const std::string& url,ARMA_FN_HTTP rx,const VARK_NVP_MAP& fields);
        void            _rx(const uint8_t* d,size_t s);
        void            _scavenge();
        void            _sendRequest(uint32_t phase);
//      PHASES
        void            _preflight(const uint8_t* d,size_t s);
        void            _measure(const uint8_t* d,size_t s);
        void            _execute(const uint8_t* d,size_t s);
//
#if ARMA_DEBUG
        void            _dumphdrs(VARK_NVP_MAP* pm){ for(auto const& p:*pm) Serial.printf("%s=%s\n",p.first.c_str(),p.second.c_str()); }
        void            _dumpreq(){ _dumphdrs(&requestHeaders); }
        void            _dumpres(){ _dumphdrs(&_response.responseHeaders); }
#endif
//
    public:
        VARK_NVP_MAP    requestHeaders;
        ArmadilloHTTP();

        void            addRequestHeader(const std::string& hdr,const std::string& value){ requestHeaders[uppercase(hdr)]=value; }
        void            onHTTPerror(VARK_cbError callback){ onTCPerror(callback); }

        virtual void    DELETE(const std::string& url,ARMA_FN_HTTP rx,const uint8_t* fingerprint=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ _prepare(phase,"DELETE",url,rx,{}); }
        virtual void    GET(const std::string& url,ARMA_FN_HTTP rx,const uint8_t* fingerprint=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ _prepare(phase,"GET",url,rx,{}); }
        virtual void    PATCH(const std::string& url,const VARK_NVP_MAP& fields,ARMA_FN_HTTP rx,const uint8_t* fingerprint=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ _prepare(phase,"PATCH",url,rx,fields); }
        virtual void    POST(const std::string& url,const VARK_NVP_MAP& fields,ARMA_FN_HTTP rx,const uint8_t* fingerprint=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ _prepare(phase,"POST",url,rx,fields); }
        virtual void    PUT(const std::string& url,const VARK_NVP_MAP& fields,ARMA_FN_HTTP rx,const uint8_t* fingerprint=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ _prepare(phase,"PUT",url,rx,fields); }
};