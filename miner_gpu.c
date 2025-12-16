// miner_gpu.c — GPU miner kompatybilny z API jak w miner_cpu.go
// Endpoints: GET /getWork  (bez auth),  POST /submitWork (X-API-Key)
// CLI:
//   ./miner_gpu.exe BASE_URL API_KEY MINER_ADDRESS START_NONCE [TRIES_PER_ROUND] [READS_PER_TRY] [DIFFICULTY]
//
// Kompilacja (MSYS2/MinGW):
//   gcc -O3 miner_gpu.c -I/mingw64/include -L/mingw64/lib -lOpenCL -lcurl -lssl -lcrypto -o miner_gpu.exe

#define CL_TARGET_OPENCL_VERSION 120

#include <CL/cl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <math.h>
#include <ctype.h>

#ifdef _WIN32
  #include <windows.h>
  static void sleep_ms(unsigned ms){ Sleep(ms); }
#else
  #include <unistd.h>
  #include <time.h>
  static void sleep_ms(unsigned ms){
    struct timespec ts; ts.tv_sec = ms/1000; ts.tv_nsec = (ms%1000)*1000000L; nanosleep(&ts,NULL);
  }
#endif

// ---- limity buforów hosta/kernelu ----
#define MAX_INBUF   1024  // header_len + 8 + 64 musi się zmieścić
#define WG_SIZE     512

// ---- URL helpers ----
static void build_url(char *out, size_t cap, const char* base, const char* endpoint) {
    size_t n = strlen(base);
    if (n>0 && base[n-1]=='/')
        snprintf(out, cap, "%s%s", base, endpoint[0]=='/'? endpoint+1 : endpoint);
    else
        snprintf(out, cap, "%s/%s", base, endpoint[0]=='/'? endpoint+1 : endpoint);
}

// -------------------- utils --------------------

static void trim_spaces(char* s){
    size_t n = strlen(s);
    while (n && (s[n-1]==' '||s[n-1]=='\n'||s[n-1]=='\r'||s[n-1]=='\t')) { s[--n]=0; }
    size_t i=0; while (s[i]==' '||s[i]=='\n'||s[i]=='\r'||s[i]=='\t') i++;
    if(i) memmove(s, s+i, strlen(s+i)+1);
}

static void strip_0x(char* s){
    if (s[0]=='0' && (s[1]=='x'||s[1]=='X')) memmove(s,s+2,strlen(s+2)+1);
}

static int hexval(char c){
    return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:-1;
}

static int hex_to_bytes(const char* hex, unsigned char* out, size_t* out_len){
    size_t n=strlen(hex); if(n%2) return -1;
    size_t bytes=n/2;
    for(size_t i=0;i<bytes;i++){
        int hi=hexval(hex[2*i]);
        int lo=hexval(hex[2*i+1]);
        if(hi<0||lo<0)return-2;
        out[i]=(hi<<4)|lo;
    }
    *out_len=bytes; return 0;
}

static void bytes_to_hex(const unsigned char* in, size_t len, char* out){
    static const char* H="0123456789abcdef";
    for(size_t i=0;i<len;i++){
        unsigned char b=in[i];
        out[2*i]=H[b>>4];
        out[2*i+1]=H[b&0xF];
    }
    out[2*len]=0;
}

static double now_seconds(void){
#ifdef _WIN32
    static LARGE_INTEGER f={0}; LARGE_INTEGER c;
    if(!f.QuadPart) QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart/(double)f.QuadPart;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec/1e9;
#endif
}

static void str_to_lower(char* s){
    while (*s) {
        *s = (char)tolower((unsigned char)*s);
        s++;
    }
}

// -------------------- OpenCL kernel (SHA-512 inline) --------------------

static const char* KERNEL_SRC =
"// OpenCL kernel: SHA-512-based PoW\n"
"#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable\n"
"#pragma OPENCL EXTENSION cl_khr_int64_base_atomics     : enable\n"
"\n"
"constant ulong K[80] = {\n"
"  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,\n"
"  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,\n"
"  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,\n"
"  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,\n"
"  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,\n"
"  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,\n"
"  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,\n"
"  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,\n"
"  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,\n"
"  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,\n"
"  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,\n"
"  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,\n"
"  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,\n"
"  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,\n"
"  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,\n"
"  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,\n"
"  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,\n"
"  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,\n"
"  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,\n"
"  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL\n"
"};\n"
"\n"
"#define ROTR64(x,n) ( ((x) >> (ulong)(n)) | ((x) << (ulong)(64-(n))) )\n"
"#define SHR(x,n)    ( (x) >> (ulong)(n) )\n"
"#define Ch(x,y,z)   ( ((x) & (y)) ^ (~(x) & (z)) )\n"
"#define Maj(x,y,z)  ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )\n"
"#define S0(x)       ( ROTR64((x),28) ^ ROTR64((x),34) ^ ROTR64((x),39) )\n"
"#define S1(x)       ( ROTR64((x),14) ^ ROTR64((x),18) ^ ROTR64((x),41) )\n"
"#define s0(x)       ( ROTR64((x),1)  ^ ROTR64((x),8)  ^ SHR((x),7) )\n"
"#define s1(x)       ( ROTR64((x),19) ^ ROTR64((x),61) ^ SHR((x),6) )\n"
"\n"
"inline void sha512(const __private uchar* msg, uint len, __private uchar out[64]) {\n"
"  const uint total = len + 1 + 16;\n"
"  const uint rem   = (total % 128);\n"
"  const uint pad   = (rem == 0) ? 0 : (128 - rem);\n"
"  const uint L     = len + 1 + pad + 16;\n"
"  __private uchar buf[512];\n"
"\n"
"  for (uint i = 0; i < len; i++) buf[i] = msg[i];\n"
"  buf[len] = (uchar)0x80;\n"
"  for (uint i = 0; i < pad; i++) buf[len + 1 + i] = (uchar)0x00;\n"
"  for (int i = 0; i < 8; i++) buf[L - 16 + i] = (uchar)0x00;\n"
"  ulong bits = ((ulong)len) * 8UL;\n"
"  for (int i = 0; i < 8; i++) buf[L - 8 + i] = (uchar)((bits >> (56 - 8 * i)) & 0xff);\n"
"\n"
"  ulong H0 = 0x6a09e667f3bcc908UL, H1 = 0xbb67ae8584caa73bUL;\n"
"  ulong H2 = 0x3c6ef372fe94f82bUL, H3 = 0xa54ff53a5f1d36f1UL;\n"
"  ulong H4 = 0x510e527fade682d1UL, H5 = 0x9b05688c2b3e6c1fUL;\n"
"  ulong H6 = 0x1f83d9abfb41bd6bUL, H7 = 0x5be0cd19137e2179UL;\n"
"\n"
"  for (uint off = 0; off < L; off += 128) {\n"
"    ulong W[80];\n"
"    for (int i = 0; i < 16; i++) {\n"
"      const __private uchar* p = buf + off + 8 * i;\n"
"      ulong w = ((ulong)p[0] << 56) | ((ulong)p[1] << 48) | ((ulong)p[2] << 40) | ((ulong)p[3] << 32)\n"
"              | ((ulong)p[4] << 24) | ((ulong)p[5] << 16) | ((ulong)p[6] << 8)  | ((ulong)p[7]);\n"
"      W[i] = w;\n"
"    }\n"
"    for (int t = 16; t < 80; t++) W[t] = s1(W[t - 2]) + W[t - 7] + s0(W[t - 15]) + W[t - 16];\n"
"\n"
"    ulong a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;\n"
"    for (int t = 0; t < 80; t++) {\n"
"      ulong T1 = h + S1(e) + Ch(e, f, g) + K[t] + W[t];\n"
"      ulong T2 = S0(a) + Maj(a, b, c);\n"
"      h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;\n"
"    }\n"
"    H0 += a; H1 += b; H2 += c; H3 += d; H4 += e; H5 += f; H6 += g; H7 += h;\n"
"  }\n"
"\n"
"  ulong H[8] = { H0, H1, H2, H3, H4, H5, H6, H7 };\n"
"  for (int i = 0; i < 8; i++)\n"
"    for (int j = 0; j < 8; j++)\n"
"      out[i * 8 + j] = (uchar)((H[i] >> (56 - 8 * j)) & 0xff);\n"
"}\n"
"\n"
"kernel void pow_try(\n"
"  __global const uchar* header,\n"
"  const uint   header_len,\n"
"  const ulong  start_nonce,\n"
"  const uint   tries,\n"
"  const uint   reads_per_try,\n"
"  const int    difficulty,\n"
"  __global ulong* out_nonce,\n"
"  __global uchar* out_mix)\n"
"{\n"
"  const ulong idx = (ulong)get_global_id(0);\n"
"  if (idx >= (ulong)tries) return;\n"
"\n"
"  ulong n = start_nonce + idx;\n"
"  uchar rolling[64]; for (int i = 0; i < 64; i++) rolling[i] = (uchar)0;\n"
"\n"
"  const uint R = (reads_per_try > 0) ? reads_per_try : 2048u;\n"
"  for (uint j = 0; j < R; j++) {\n"
"    int k = (int)((n + (ulong)j) % 64UL);\n"
"    rolling[k] ^= (uchar)((n >> ((j & 7u) * 8u)) & 0xffUL);\n"
"  }\n"
"\n"
"  const uint inLen = header_len + 8u + 64u;\n"
"  uchar inbuf[1024];\n"
"  for (uint i = 0; i < header_len; i++) inbuf[i] = header[i];\n"
"  inbuf[header_len + 0] = (uchar)((n >> 56) & 0xffUL);\n"
"  inbuf[header_len + 1] = (uchar)((n >> 48) & 0xffUL);\n"
"  inbuf[header_len + 2] = (uchar)((n >> 40) & 0xffUL);\n"
"  inbuf[header_len + 3] = (uchar)((n >> 32) & 0xffUL);\n"
"  inbuf[header_len + 4] = (uchar)((n >> 24) & 0xffUL);\n"
"  inbuf[header_len + 5] = (uchar)((n >> 16) & 0xffUL);\n"
"  inbuf[header_len + 6] = (uchar)((n >> 8)  & 0xffUL);\n"
"  inbuf[header_len + 7] = (uchar)((n >> 0)  & 0xffUL);\n"
"  for (int i = 0; i < 64; i++) inbuf[header_len + 8 + i] = rolling[i];\n"
"\n"
"  uchar h[64];\n"
"  sha512((const __private uchar*)inbuf, inLen, h);\n"
"\n"
"  ulong last8 = 0UL; for (int i = 0; i < 8; i++) last8 = (last8 << 8) | (ulong)h[56 + i];\n"
"  ulong mask = (difficulty <= 0) ? 0UL : (difficulty >= 64 ? (ulong)(-1) : (((ulong)1 << (ulong)difficulty) - (ulong)1));\n"
"\n"
"  if ((last8 & mask) == 0UL) {\n"
"    if (atom_cmpxchg((volatile __global ulong*)out_nonce, (ulong)0, n) == (ulong)0) {\n"
"      for (int i = 0; i < 64; i++) out_mix[i] = h[i];\n"
"    }\n"
"  }\n"
"}\n";

// ---- Energy report do Boson Oracle ----

static void send_energy_report(const char* oracleUrl,
                               const char* minerId,
                               double hashrateHps,
                               double powerWatts)
{
    if (!oracleUrl || !*oracleUrl) return;
    if (!minerId || !*minerId) return;
    if (hashrateHps <= 0.0 || powerWatts <= 0.0) return;

    const char* secret = getenv("BFI_ORACLE_SECRET");
    if (!secret || !*secret) {
        return;
    }

    time_t now = time(NULL);
    long long ts = (long long)now;

    char msg[256];
    snprintf(msg, sizeof(msg), "%s|%.6f|%.6f|%lld", minerId, hashrateHps, powerWatts, ts);

    unsigned char mac[32];
    unsigned int maclen = 0;
    HMAC(EVP_sha256(), secret, (int)strlen(secret),
         (unsigned char*)msg, (int)strlen(msg),
         mac, &maclen);

    char sigHex[65];
    for (unsigned int i = 0; i < maclen; i++) {
        sprintf(sigHex + i * 2, "%02x", mac[i]);
    }
    sigHex[64] = 0;

    CURL* curl = curl_easy_init();
    if (!curl) return;

    char url[512];
    snprintf(url, sizeof(url), "%s/v1/miner/report", oracleUrl);

    char body[512];
    snprintf(body, sizeof(body),
        "{\"miner_id\":\"%s\",\"hashrate_hps\":%.6f,\"power_watts\":%.6f,\"reported_at\":%lld,\"sig\":\"%s\"}",
        minerId, hashrateHps, powerWatts, ts, sigHex);

    struct curl_slist* hdr = NULL;
    hdr = curl_slist_append(hdr, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    CURLcode res = curl_easy_perform(curl);
    (void)res;

    if (hdr) curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);
}


// ---------------- libcurl + json helpers ----------------

struct memchunk { char* data; size_t size; };
static size_t wcb(void* ptr,size_t sz,size_t nm,void* ud){
    size_t b=sz*nm;
    struct memchunk*m=(struct memchunk*)ud;
    char*p=realloc(m->data,m->size+b+1);
    if(!p)return 0;
    m->data=p;
    memcpy(m->data+m->size,ptr,b);
    m->size+=b;
    m->data[m->size]=0;
    return b;
}

static int json_get_string(const char* json,const char* key,char*out,size_t outsz){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    const char*k=strstr(json,pat); if(!k)return 0;
    const char*q=strchr(k+strlen(pat),':'); if(!q)return 0;
    const char*s=strchr(q,'\"'); if(!s)return 0; s++;
    const char*e=strchr(s,'\"'); if(!e)return 0;
    size_t n=e-s; if(n>=outsz) n=outsz-1; memcpy(out,s,n); out[n]=0; return 1;
}
static int json_get_uint(const char* json,const char* key,unsigned int*out){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    const char*k=strstr(json,pat); if(!k)return 0;
    const char*q=strchr(k+strlen(pat),':'); if(!q)return 0;
    *out=(unsigned int)strtoul(q+1,NULL,10); return 1;
}
static int json_get_uint64(const char* json,const char* key,unsigned long long*out){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    const char*k=strstr(json,pat); if(!k)return 0;
    const char*q=strchr(k+strlen(pat),':'); if(!q)return 0;
    *out=strtoull(q+1,NULL,10); return 1;
}
static int json_get_double(const char* json,const char* key,double*out){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    const char*k=strstr(json,pat); if(!k)return 0;
    const char*q=strchr(k+strlen(pat),':'); if(!q)return 0;
    *out=strtod(q+1,NULL); return 1;
}

// --- parsowanie ceny z API energy-charts (price[] w EUR/MWh) ---

static double parse_latest_price_eur_per_mwh(const char* json) {
    if (!json) return 0.0;
    const char* p = strstr(json, "\"price\"");
    if (!p) return 0.0;
    p = strchr(p, '[');
    if (!p) return 0.0;
    p++; // za '['
    double last = 0.0;
    int found = 0;
    while (*p && *p != ']') {
        char* endptr = NULL;
        double v = strtod(p, &endptr);
        if (endptr == p) { // nie było liczby – przeskocz znak
            p++;
            continue;
        }
        last = v;
        found = 1;
        p = endptr;
    }
    if (!found) return 0.0;
    return last; // EUR/MWh
}

static double fetch_price_eur_per_mwh(const char* apiUrl) {
    if (!apiUrl || !*apiUrl) return 0.0;

    CURL* curl = curl_easy_init();
    if (!curl) return 0.0;

    struct memchunk m = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wcb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_URL, apiUrl);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    }

    double price = 0.0;
    if (res == CURLE_OK && code == 200 && m.data) {
        price = parse_latest_price_eur_per_mwh(m.data);
        if (price > 0.0) {
            printf("[price-api] latest=%.2f EUR/MWh\n", price);
        } else {
            fprintf(stderr, "[price-api] parse failed\n");
        }
    } else {
        fprintf(stderr, "[price-api] HTTP err res=%d code=%ld\n", (int)res, code);
    }

    if (m.data) free(m.data);
    curl_easy_cleanup(curl);
    return price;
}

// --- stats z noda: /stats -> energy_price_per_kwh, cost_per_coin itd. ---

static int fetch_node_economy(const char* baseUrl,
                              double* pricePerKWh,
                              double* costPerCoin,
                              double* costPerBlock,
                              double* costPerHash,
                              char* currency,
                              size_t currencyCap)
{
    if (!baseUrl || !*baseUrl) return 0;

    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    char u1[512], u2[512];
    build_url(u1, sizeof(u1), baseUrl, "/stats");
    build_url(u2, sizeof(u2), baseUrl, "/api/stats");

    struct memchunk m = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wcb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_URL, u1);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    }

    if (res == CURLE_OK && code == 404) {
        if (m.data) { free(m.data); m.data = NULL; m.size = 0; }
        curl_easy_setopt(curl, CURLOPT_URL, u2);
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        }
    }

    int ok = 0;
    if (res == CURLE_OK && code == 200 && m.data) {
        double p=0.0, ccoin=0.0, cblock=0.0, chash=0.0;
        char cur[16] = {0};

        json_get_double(m.data, "energy_price_per_kwh", &p);
        json_get_double(m.data, "cost_per_coin",        &ccoin);
        json_get_double(m.data, "cost_per_block",       &cblock);
        json_get_double(m.data, "cost_per_hash",        &chash);
        json_get_string(m.data, "fiat_currency",        cur, sizeof(cur));

        if (pricePerKWh)  *pricePerKWh  = p;
        if (costPerCoin)  *costPerCoin  = ccoin;
        if (costPerBlock) *costPerBlock = cblock;
        if (costPerHash)  *costPerHash  = chash;
        if (currency && currencyCap > 0) {
            if (cur[0]) snprintf(currency, currencyCap, "%s", cur);
            else snprintf(currency, currencyCap, "%s", "EUR");
        }
        ok = 1;
    }

    if (m.data) free(m.data);
    curl_easy_cleanup(curl);
    return ok;
}

// -------- CPU-compatible endpoints: /getWork & /submitWork --------

// tutaj trzymamy ostatnio zwrócone nagrody (w BOS)
static double gLastMinerReward = 0.0; // to idzie do Ciebie
static double gLastStakeReward = 0.0; // to idzie do stakerów
static double gLastTotalReward = 0.0; // cała nagroda bloku

// -------- getWork --------
static int get_work(const char* baseUrl,
                    char* headerHex_out,size_t headerHex_cap,
                    unsigned int* diff_io,unsigned int* reads_io,
                    char* jobId_out,size_t jobId_cap,
                    unsigned long long* exp_io)
{
    CURL* curl=curl_easy_init(); if(!curl)return 0;
    char u1[512],u2[512];
    build_url(u1,sizeof(u1),baseUrl,"/getWork");
    build_url(u2,sizeof(u2),baseUrl,"/api/getWork");
    struct memchunk m={0};
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,wcb);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,&m);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,5L);
    curl_easy_setopt(curl,CURLOPT_URL,u1);
    CURLcode res=curl_easy_perform(curl); long code=0;
    if(res==CURLE_OK)curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&code);

    if(res==CURLE_OK&&code==404){
        if(m.data){free(m.data);m.data=NULL;m.size=0;}
        curl_easy_setopt(curl,CURLOPT_URL,u2);
        res=curl_easy_perform(curl);
        if(res==CURLE_OK)curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&code);
    }

    int updated=0;
    if(res==CURLE_OK&&code==200&&m.data){
        char head[4096]={0},job[256]={0};
        unsigned int diff=*diff_io,reads=*reads_io;
        unsigned long long exp=*exp_io;
        double minerRew=0.0, stakeRew=0.0, totalRew=0.0;

        if(json_get_string(m.data,"header_hex",head,sizeof(head)) ||
           json_get_string(m.data,"header",head,sizeof(head)))
        {
            trim_spaces(head);
            strip_0x(head);
            strncpy(headerHex_out,head,headerHex_cap-1);
            updated=1;
        }

        if(!json_get_uint(m.data,"difficulty",&diff))
            json_get_uint(m.data,"difficulty_bits",&diff);

        if(!json_get_uint(m.data,"reads",&reads))
            json_get_uint(m.data,"reads_per_try",&reads);

        if(json_get_string(m.data,"job_id",job,sizeof(job)))
            strncpy(jobId_out,job,jobId_cap-1);

        if(!json_get_uint64(m.data,"expires_at",&exp))
            json_get_uint64(m.data,"expires_at_unix",&exp);

        json_get_double(m.data,"miner_reward",&minerRew);
        json_get_double(m.data,"stake_reward",&stakeRew);
        json_get_double(m.data,"total_reward",&totalRew);

        *diff_io=diff;
        *reads_io=reads;
        *exp_io=exp;

        gLastMinerReward = minerRew;
        gLastStakeReward = stakeRew;
        gLastTotalReward = totalRew;

        printf("[getWork] diff=%u reads=%u exp=%llu miner=%.6f stake=%.6f total=%.6f\n",
               diff,reads,exp,minerRew,stakeRew,totalRew);
    }

    if(m.data)free(m.data);
    curl_easy_cleanup(curl);
    return updated;
}

// -------- submitWork --------
static int post_submit_work(const char* base,const char* api,
                            const char* addr,const char* head,
                            unsigned long long nonce,const char* mix,
                            const char* job)
{
    CURL* curl=curl_easy_init(); if(!curl)return -1;
    char u1[512]; build_url(u1,sizeof(u1),base,"/submitWork");
    char json[4096];
    snprintf(json,sizeof(json),
        "{\"header_hex\":\"%s\",\"nonce\":%llu,\"mix_hex\":\"%s\",\"miner_address\":\"%s\",\"job_id\":\"%s\"}",
        head,nonce,mix,addr,job?job:"");
    struct curl_slist*hdr=NULL;
    hdr=curl_slist_append(hdr,"Content-Type: application/json");
    if(api&&*api){
        char b[256];snprintf(b,sizeof(b),"X-API-Key: %s",api);
        hdr=curl_slist_append(hdr,b);
    }
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,hdr);
    curl_easy_setopt(curl,CURLOPT_POSTFIELDS,json);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,5L);
    curl_easy_setopt(curl,CURLOPT_URL,u1);
    CURLcode res=curl_easy_perform(curl); long code=0;
    if(res==CURLE_OK)curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&code);
    if(hdr)curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);
    return (int)code;
}

// -------------------- OpenCL arg helper --------------------

static cl_int set_args_cl(cl_command_queue q,cl_kernel krn,
                          cl_mem headerBuf,const unsigned char* headerBytes,size_t headerLen,
                          cl_mem outNonceBuf,cl_ulong startNonce,
                          cl_uint tries,cl_uint reads,cl_int diff)
{
    cl_int e;
    e = clEnqueueWriteBuffer(q,headerBuf,CL_TRUE,0,headerLen,headerBytes,0,NULL,NULL);
    if(e!=CL_SUCCESS)return e;

    cl_ulong z=0;
    e |= clEnqueueWriteBuffer(q,outNonceBuf,CL_TRUE,0,sizeof(z),&z,0,NULL,NULL);

    cl_uint hl=(cl_uint)headerLen;
    e |= clSetKernelArg(krn,0,sizeof(cl_mem),&headerBuf);
    e |= clSetKernelArg(krn,1,sizeof(cl_uint),&hl);
    e |= clSetKernelArg(krn,2,sizeof(cl_ulong),&startNonce);
    e |= clSetKernelArg(krn,3,sizeof(cl_uint),&tries);
    e |= clSetKernelArg(krn,4,sizeof(cl_uint),&reads);
    e |= clSetKernelArg(krn,5,sizeof(cl_int),&diff);
    e |= clSetKernelArg(krn,6,sizeof(cl_mem),&outNonceBuf);
    return e;
}

// ---- auto-detect mocy GPU po nazwie / compute units ----

static double guess_power_watts_from_device(cl_device_id device, char* outName, size_t outNameCap) {
    char name[256]   = {0};
    char vendor[256] = {0};
    clGetDeviceInfo(device, CL_DEVICE_NAME,   sizeof(name),   name,   NULL);
    clGetDeviceInfo(device, CL_DEVICE_VENDOR, sizeof(vendor), vendor, NULL);

    if (outName && outNameCap > 0) {
        snprintf(outName, outNameCap, "%s", name);
    }

    char nameL[256]; snprintf(nameL, sizeof(nameL), "%s", name);
    str_to_lower(nameL);

    // typowe TDP kart (pełne obciążenie, plus lekki zapas pod rig)
    if (strstr(nameL, "rtx 5090")) return 550.0;
    if (strstr(nameL, "rtx 4090")) return 450.0;
    if (strstr(nameL, "rtx 4080")) return 350.0;
    if (strstr(nameL, "rtx 4070")) return 260.0;
    if (strstr(nameL, "rtx 3090")) return 380.0;
    if (strstr(nameL, "rtx 3080")) return 330.0;
    if (strstr(nameL, "rtx 3070")) return 240.0;
    if (strstr(nameL, "rtx 3060")) return 200.0;

    if (strstr(nameL, "rx 7900")) return 350.0;
    if (strstr(nameL, "rx 7800")) return 300.0;
    if (strstr(nameL, "rx 7700")) return 260.0;
    if (strstr(nameL, "rx 6900")) return 320.0;
    if (strstr(nameL, "rx 6800")) return 280.0;
    if (strstr(nameL, "rx 6700")) return 230.0;

    // fallback: policz z compute units (bardzo z grubsza)
    cl_uint cus = 0;
    clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, NULL);
    if (cus > 0) {
        // 20W / CU + 80W overhead platformy
        return 20.0 * (double)cus + 80.0;
    }

    // kompletny fallback
    return 250.0;
}

// -------------------- main --------------------

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s BASE_URL API_KEY MINER_ADDRESS [START_NONCE]\n", argv[0]);
        return 1;
    }

    const char* baseUrl    = argv[1];
    const char* apiKey     = argv[2];
    const char* addressHex = argv[3];

    unsigned long long startNonce = 0ULL;
    if (argc >= 5) {
        startNonce = strtoull(argv[4], NULL, 10);
    }

    const char* minerLabel = getenv("BFI_MINER_LABEL");
    if (!minerLabel || !*minerLabel) {
        minerLabel = "gpu-miner";
    }

    // flaga: można wyłączyć price-api
    const char* priceDisabledEnv = getenv("BFI_DISABLE_PRICE_API");
    int priceApiDisabled = (priceDisabledEnv && *priceDisabledEnv) ? 1 : 0;

    // Moc rig-a [W] – najpierw ENV, potem auto z GPU
    double rigPowerWatts = 0.0;
    const char* env_power = getenv("BFI_POWER_WATTS");
    if (env_power && *env_power) {
        rigPowerWatts = atof(env_power);
    }

    // URL do energii / ceny (zewnętrzne)
    const char* oracleUrl  = getenv("BFI_ENERGY_ORACLE_URL"); // np. http://94.130.151.250:8090
    const char* priceApiUrl = getenv("BFI_PRICE_API_URL");
    if (!priceApiUrl || !*priceApiUrl) {
        priceApiUrl = "https://api.energy-charts.info/price?bzn=DE-LU";
    }

    unsigned int triesPerRound = 2000000u;
    unsigned int readsPerTry   = 2048u;
    int difficulty             = 0;

    const char* env;
    env = getenv("BFI_START_NONCE");
    if (env && *env) startNonce = strtoull(env, NULL, 10);

    env = getenv("BFI_TRIES");
    if (env && *env) triesPerRound = (unsigned int)strtoul(env, NULL, 10);

    env = getenv("BFI_READS");
    if (env && *env) readsPerTry = (unsigned int)strtoul(env, NULL, 10);

    env = getenv("BFI_DIFF");
    if (env && *env) difficulty = atoi(env);

    char headerHex[4096] = {0};
    char curJobId[256]   = {0};
    unsigned long long jobExpires = 0;

    unsigned int diff_tmp = (unsigned int)difficulty;
    unsigned int rpt_tmp  = readsPerTry;

    if (!get_work(baseUrl, headerHex, sizeof(headerHex),
                  &diff_tmp, &rpt_tmp,
                  curJobId, sizeof(curJobId),
                  &jobExpires)) {
        fprintf(stderr, "[%s ERR] getWork failed (sprawdz node i port)\n", minerLabel);
        return 2;
    }

    const char* fenv = getenv("MINER_FORCE_DIFF");
    if (fenv && *fenv) difficulty = atoi(fenv);

    difficulty  = (int)diff_tmp;
    readsPerTry = (rpt_tmp > 0) ? rpt_tmp : 2048u;

    trim_spaces(headerHex);
    strip_0x(headerHex);

    unsigned char* headerBytes = (unsigned char*)malloc(MAX_INBUF);
    if (!headerBytes) {
        fprintf(stderr, "[%s ERR] oom headerBytes\n", minerLabel);
        return 3;
    }
    size_t headerLen = 0;
    if (hex_to_bytes(headerHex, headerBytes, &headerLen) != 0) {
        fprintf(stderr, "[%s ERR] bad header_hex from server\n", minerLabel);
        free(headerBytes);
        return 3;
    }
    if (headerLen + 8 + 64 > MAX_INBUF) {
        fprintf(stderr, "[%s ERR] header too long (%zu bytes). Max header = %d\n",
                minerLabel, headerLen, (int)(MAX_INBUF - 72));
        free(headerBytes);
        return 3;
    }

    printf("[%s] base=%s addr=%s startNonce=%llu triesPerRound=%u readsPerTry=%u difficulty=%d job=%s exp=%llu headerLen=%zu\n",
           minerLabel,
           baseUrl, addressHex,
           (unsigned long long)startNonce,
           triesPerRound, readsPerTry, difficulty,
           (curJobId[0] ? curJobId : "-"),
           jobExpires, headerLen);

    curl_global_init(CURL_GLOBAL_ALL);

    cl_int err = 0;

    cl_uint numPlatforms = 0;
    clGetPlatformIDs(0, NULL, &numPlatforms);
    if (numPlatforms == 0) {
        fprintf(stderr, "[%s ERR] No OpenCL platforms\n", minerLabel);
        free(headerBytes);
        return 4;
    }

    cl_platform_id *platforms = (cl_platform_id*)malloc(sizeof(cl_platform_id) * numPlatforms);
    clGetPlatformIDs(numPlatforms, platforms, NULL);

    cl_device_id device = NULL;
    for (cl_uint p = 0; p < numPlatforms && !device; p++) {
        cl_uint numDevices = 0;
        clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 0, NULL, &numDevices);
        if (numDevices) {
            cl_device_id *devices = (cl_device_id*)malloc(sizeof(cl_device_id)*numDevices);
            clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, numDevices, devices, NULL);
            device = devices[0];
            free(devices);
        }
    }
    if (!device) {
        fprintf(stderr, "[%s WARN] No GPU device, trying CPU...\n", minerLabel);
        for (cl_uint p = 0; p < numPlatforms && !device; p++) {
            cl_uint numDevices = 0;
            clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_CPU, 0, NULL, &numDevices);
            if (numDevices) {
                cl_device_id *devices = (cl_device_id*)malloc(sizeof(cl_device_id)*numDevices);
                clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_CPU, numDevices, devices, NULL);
                device = devices[0];
                free(devices);
            }
        }
    }
    if (!device) {
        fprintf(stderr, "[%s ERR] No OpenCL device\n", minerLabel);
        free(platforms);
        free(headerBytes);
        return 5;
    }

    // auto-detekcja poboru mocy jeśli nie ustawiono ENV
    char gpuName[256] = {0};
    if (rigPowerWatts <= 0.0) {
        rigPowerWatts = guess_power_watts_from_device(device, gpuName, sizeof(gpuName));
        if (gpuName[0]) {
            printf("[%s] auto GPU=\"%s\" -> power~%.1f W\n", minerLabel, gpuName, rigPowerWatts);
        } else {
            printf("[%s] auto GPU power~%.1f W\n", minerLabel, rigPowerWatts);
        }
    } else {
        clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(gpuName), gpuName, NULL);
        if (gpuName[0]) {
            printf("[%s] GPU=\"%s\" power from ENV=%.1f W\n", minerLabel, gpuName, rigPowerWatts);
        } else {
            printf("[%s] power from ENV=%.1f W\n", minerLabel, rigPowerWatts);
        }
    }

    cl_context ctx = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "[%s ERR] clCreateContext=%d\n", minerLabel, err);
        free(platforms);
        free(headerBytes);
        return 6;
    }

    cl_command_queue q = NULL;
#ifdef CL_VERSION_2_0
    const cl_queue_properties props[] = { 0 };
    q = clCreateCommandQueueWithProperties(ctx, device, props, &err);
    if (err != CL_SUCCESS)
#endif
    {
        q = clCreateCommandQueue(ctx, device, 0, &err);
    }
    if (err != CL_SUCCESS || !q) {
        fprintf(stderr, "[%s ERR] clCreateCommandQueue=%d\n", minerLabel, err);
        clReleaseContext(ctx);
        free(platforms);
        free(headerBytes);
        return 7;
    }

    const char* src = KERNEL_SRC;
    size_t srclen = strlen(src);
    cl_program prog = clCreateProgramWithSource(ctx, 1, &src, &srclen, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "[%s ERR] clCreateProgramWithSource=%d\n", minerLabel, err);
        clReleaseCommandQueue(q);
        clReleaseContext(ctx);
        free(platforms);
        free(headerBytes);
        return 8;
    }

    err = clBuildProgram(prog, 1, &device, "", NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t logSize = 0;
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &logSize);
        char *log = (char*)malloc(logSize + 1);
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, logSize, log, NULL);
        log[logSize] = 0;
        fprintf(stderr, "[%s Build log]\n%s\n", minerLabel, log);
        free(log);
        fprintf(stderr, "[%s ERR] clBuildProgram=%d\n", minerLabel, err);
        clReleaseProgram(prog);
        clReleaseCommandQueue(q);
        clReleaseContext(ctx);
        free(platforms);
        free(headerBytes);
        return 9;
    }

    cl_kernel krn = clCreateKernel(prog, "pow_try", &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "[%s ERR] clCreateKernel=%d\n", minerLabel, err);
        clReleaseProgram(prog);
        clReleaseCommandQueue(q);
        clReleaseContext(ctx);
        free(platforms);
        free(headerBytes);
        return 10;
    }

    cl_mem headerBuf  = clCreateBuffer(ctx, CL_MEM_READ_ONLY, headerLen, NULL, &err);
    cl_mem outNonceBuf= clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(cl_ulong), NULL, &err);
    cl_mem outMixBuf  = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 64, NULL, &err);
    if (err != CL_SUCCESS || !headerBuf || !outNonceBuf || !outMixBuf) {
        fprintf(stderr, "[%s ERR] clCreateBuffer=%d\n", minerLabel, err);
        return 11;
    }

    err = clSetKernelArg(krn, 7, sizeof(cl_mem), &outMixBuf);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "[%s ERR] clSetKernelArg(out_mix)=%d\n", minerLabel, err);
        return 12;
    }

    if (set_args_cl(q, krn, headerBuf, headerBytes, headerLen, outNonceBuf,
                    (cl_ulong)startNonce, (cl_uint)triesPerRound,
                    (cl_uint)readsPerTry, (cl_int)difficulty) != CL_SUCCESS) {
        return 13;
    }

    // cache dla cen
    static double gLastPriceEurPerMWh = 0.0;
    static double gLastPriceFetchTs   = 0.0;

    static double gNodeEnergyPricePerKWh = 0.0;
    static double gNodeCostPerCoin       = 0.0;
    static double gNodeCostPerBlock      = 0.0;
    static double gNodeCostPerHash       = 0.0;
    static char   gNodeCurrency[16]      = "EUR";
    static double gLastNodeStatsTs       = 0.0;

    // na start: pobierz /stats z noda
    double tInit = now_seconds();
    double pKWh=0.0, cCoin=0.0, cBlock=0.0, cHash=0.0;
    char cur[16] = {0};
    if (fetch_node_economy(baseUrl, &pKWh, &cCoin, &cBlock, &cHash, cur, sizeof(cur))) {
        gNodeEnergyPricePerKWh = pKWh;
        gNodeCostPerCoin       = cCoin;
        gNodeCostPerBlock      = cBlock;
        gNodeCostPerHash       = cHash;
        if (cur[0]) snprintf(gNodeCurrency, sizeof(gNodeCurrency), "%s", cur);
        gLastNodeStatsTs = tInit;

        if (gNodeEnergyPricePerKWh > 0.0 && gLastPriceEurPerMWh <= 0.0) {
            gLastPriceEurPerMWh = gNodeEnergyPricePerKWh * 1000.0; // kWh -> MWh
            gLastPriceFetchTs   = tInit;
        }

        printf("[node stats] energy_price_per_kwh=%.6f %s/kWh cost_per_coin=%.6f %s\n",
               gNodeEnergyPricePerKWh, gNodeCurrency,
               gNodeCostPerCoin, gNodeCurrency);
    }

    double lastPoll = 0.0;
    unsigned long long rounds = 0;
    unsigned long long lastTotalTries = 0;
    unsigned long long totalTries = 0;
    unsigned long long acceptedShares = 0;
    unsigned long long foundBlocks    = 0;

    for (;;) {
        double tNow = now_seconds();
        if (tNow - lastPoll > 1.5) {
            lastPoll = tNow;

            char newHeaderHex[4096]={0};
            char newJobId[256]={0};
            unsigned long long newExp=0;
            unsigned int newDiff = (unsigned int)difficulty;
            unsigned int newRpt  = readsPerTry;

            if (get_work(baseUrl, newHeaderHex, sizeof(newHeaderHex),
                         &newDiff, &newRpt,
                         newJobId, sizeof(newJobId),
                         &newExp))
            {
                trim_spaces(newHeaderHex);
                strip_0x(newHeaderHex);
                size_t nlen=0;
                unsigned char* tmp = (unsigned char*)malloc(MAX_INBUF);
                if (tmp && hex_to_bytes(newHeaderHex, tmp, &nlen)==0 &&
                    (nlen + 8 + 64 <= MAX_INBUF))
                {
                    int jobChanged = (curJobId[0] || newJobId[0])
                                     ? strcmp(curJobId, newJobId) != 0
                                     : 0;
                    if (jobChanged) {
                        printf("[%s job] id=%s diff=%u reads=%u exp=%llu headerLen=%zu\n",
                               minerLabel,
                               (newJobId[0]?newJobId:"-"),
                               newDiff, newRpt, newExp, nlen);
                    }

                    if (nlen != headerLen) {
                        clReleaseMemObject(headerBuf);
                        headerBuf = clCreateBuffer(ctx, CL_MEM_READ_ONLY, nlen, NULL, &err);
                        if (err != CL_SUCCESS || !headerBuf) {
                            fprintf(stderr, "[%s ERR] re-create header buf=%d\n", minerLabel, err);
                            free(tmp);
                            break;
                        }
                        headerLen = nlen;
                    }
                    memcpy(headerBytes, tmp, nlen);
                    free(tmp);

                    strncpy(headerHex, newHeaderHex, sizeof(headerHex)-1);
                    headerHex[sizeof(headerHex)-1] = 0;

                    strncpy(curJobId, newJobId, sizeof(curJobId)-1);
                    jobExpires = newExp;
                    difficulty = (int)newDiff;
                    readsPerTry = (newRpt>0?newRpt:2048u);

                    if (set_args_cl(q, krn, headerBuf, headerBytes, headerLen, outNonceBuf,
                                    (cl_ulong)startNonce, (cl_uint)triesPerRound,
                                    (cl_uint)readsPerTry, (cl_int)difficulty) != CL_SUCCESS) {
                        break;
                    }
                } else {
                    if (tmp) free(tmp);
                }
            }
        }

        size_t g = (size_t)triesPerRound;
        size_t l = WG_SIZE;
        if (g % l != 0) g = ((g + l - 1) / l) * l;

        double t0 = now_seconds();
        err = clEnqueueNDRangeKernel(q, krn, 1, NULL, &g, &l, 0, NULL, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "[%s ERR] clEnqueueNDRangeKernel=%d\n", minerLabel, err);
            break;
        }
        clFinish(q);
        double t1 = now_seconds();

        cl_ulong foundNonce = (cl_ulong)(~0ULL);
        err = clEnqueueReadBuffer(q, outNonceBuf, CL_TRUE, 0,
                                  sizeof(cl_ulong), &foundNonce,
                                  0, NULL, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "[%s ERR] read out_nonce=%d\n", minerLabel, err);
            break;
        }

        totalTries += triesPerRound;

        if (rounds % 10 == 0) {
            double dt = t1 - t0;
            double hps_real = dt > 0 ? ((double)triesPerRound / dt) : 0.0;

            double hps_disp = hps_real;
            const char* unit = "H/s";
            if (hps_disp >= 1e12) { hps_disp /= 1e12; unit = "TH/s"; }
            else if (hps_disp >= 1e9) { hps_disp /= 1e9; unit = "GH/s"; }
            else if (hps_disp >= 1e6) { hps_disp /= 1e6; unit = "MH/s"; }
            else if (hps_disp >= 1e3) { hps_disp /= 1e3; unit = "kH/s"; }

            unsigned long long batchTries = totalTries - lastTotalTries;
            unsigned long long totalAll   = totalTries;

            double estMiner = (double)foundBlocks * gLastMinerReward;
            double estStake = (double)foundBlocks * gLastStakeReward;
            double estTotal = (gLastTotalReward > 0.0)
                              ? (double)foundBlocks * gLastTotalReward
                              : (estMiner + estStake);

            double energyPerCoinKWh = 0.0;
            if (rigPowerWatts > 0.0 && hps_real > 0.0 && gLastMinerReward > 0.0 && difficulty > 0) {
                double pow2d = pow(2.0, (double)difficulty);
                double energyPerCoinJ = (rigPowerWatts * pow2d) / (hps_real * gLastMinerReward);
                energyPerCoinKWh = energyPerCoinJ / 3.6e6;
            }

            // Regularny refresh /stats z noda (co 60s)
            double tNow2 = now_seconds();
            if (tNow2 - gLastNodeStatsTs > 60.0) {
                double p2=0.0, c2=0.0, cb2=0.0, ch2=0.0;
                char cur2[16] = {0};
                if (fetch_node_economy(baseUrl, &p2, &c2, &cb2, &ch2, cur2, sizeof(cur2))) {
                    gNodeEnergyPricePerKWh = p2;
                    gNodeCostPerCoin       = c2;
                    gNodeCostPerBlock      = cb2;
                    gNodeCostPerHash       = ch2;
                    if (cur2[0]) snprintf(gNodeCurrency, sizeof(gNodeCurrency), "%s", cur2);
                    gLastNodeStatsTs = tNow2;

                    if (gNodeEnergyPricePerKWh > 0.0 && gLastPriceEurPerMWh <= 0.0) {
                        gLastPriceEurPerMWh = gNodeEnergyPricePerKWh * 1000.0;
                        gLastPriceFetchTs   = tNow2;
                    }
                }
            }

            // Zewnętrzne API tylko jako override co 10 minut
            if (!priceApiDisabled) {
                if (tNow2 - gLastPriceFetchTs > 600.0) {
                    gLastPriceFetchTs = tNow2; // żeby nie spamować przy błędach
                    double p = fetch_price_eur_per_mwh(priceApiUrl);
                    if (p > 0.0) {
                        gLastPriceEurPerMWh = p;
                    }
                }
            }

            double pricePerKWh = 0.0;
            if (gNodeEnergyPricePerKWh > 0.0) {
                pricePerKWh = gNodeEnergyPricePerKWh;
            } else if (gLastPriceEurPerMWh > 0.0) {
                pricePerKWh = gLastPriceEurPerMWh / 1000.0; // MWh -> kWh
            }

            double costPerCoinEur = 0.0;
            if (energyPerCoinKWh > 0.0 && pricePerKWh > 0.0) {
                costPerCoinEur = energyPerCoinKWh * pricePerKWh;
            }

            printf("[%s stat] %.2f %s | nonce=%llu | diff=%d | rpt=%u | batch_tries=%llu | total_tries=%llu | accepted=%llu | blocks=%llu | est_mined=%.6f BOS (you) | est_stakers=%.6f BOS | est_total=%.6f BOS | rig_power=%.1f W | E_per_coin~%.6f kWh | node_price=%.4f %s/kWh | node_cost_coin=%.6f %s | est_cost_coin~%.6f %s\n",
                   minerLabel,
                   hps_disp, unit,
                   (unsigned long long)startNonce,
                   difficulty,
                   readsPerTry,
                   batchTries,
                   totalAll,
                   acceptedShares,
                   foundBlocks,
                   estMiner,
                   estStake,
                   estTotal,
                   rigPowerWatts,
                   energyPerCoinKWh,
                   pricePerKWh,
                   gNodeCurrency,
                   gNodeCostPerCoin,
                   gNodeCurrency,
                   costPerCoinEur,
                   gNodeCurrency);

            lastTotalTries = totalTries;

            if (rigPowerWatts > 0.0 && hps_real > 0.0) {
                send_energy_report(oracleUrl, minerLabel, hps_real, rigPowerWatts);
            }
        }

        if (foundNonce != 0ULL) {
            unsigned char mix[64];
            err = clEnqueueReadBuffer(q, outMixBuf, CL_TRUE, 0, 64, mix, 0, NULL, NULL);
            if (err != CL_SUCCESS) {
                fprintf(stderr, "[%s ERR] read out_mix=%d\n", minerLabel, err);
                break;
            }
            char mixHex[129]; bytes_to_hex(mix, 64, mixHex);

            printf("[%s FOUND] nonce=%llu hash=%s\n",
                   minerLabel,
                   (unsigned long long)foundNonce, mixHex);

            int code = post_submit_work(baseUrl, apiKey, addressHex, headerHex,
                                        (unsigned long long)foundNonce, mixHex,
                                        curJobId);
            if (code > 0) {
                printf("[%s submit] HTTP %d\n", minerLabel, code);
                if (code >= 200 && code < 300) {
                    acceptedShares++;
                    foundBlocks++;
                }
            }

            startNonce = (unsigned long long)foundNonce + 1ULL;
        } else {
            startNonce += (unsigned long long)triesPerRound;
        }

        cl_ulong zero = 0;
        err  = clEnqueueWriteBuffer(q, outNonceBuf, CL_TRUE, 0,
                                    sizeof(cl_ulong), &zero,
                                    0, NULL, NULL);
        err |= clSetKernelArg(krn, 2, sizeof(cl_ulong), &startNonce);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "[%s ERR] next-round arg/write=%d\n", minerLabel, err);
            break;
        }

        rounds++;
        sleep_ms(5);
    }

    clReleaseMemObject(headerBuf);
    clReleaseMemObject(outNonceBuf);
    clReleaseMemObject(outMixBuf);
    clReleaseKernel(krn);
    clReleaseProgram(prog);
    clReleaseCommandQueue(q);
    clReleaseContext(ctx);
    free(platforms);
    free(headerBytes);

    curl_global_cleanup();
    return 0;
}
