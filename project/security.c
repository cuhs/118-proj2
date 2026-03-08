#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libsecurity.h" 
#include "io.h"
#include "consts.h"

int state_sec = 0;
char *hostname = NULL;
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;

static uint64_t read_be_uint(const uint8_t* bytes, size_t nbytes) {
    UNUSED(bytes);
    UNUSED(nbytes);
    // TODO: parse an unsigned integer from a big-endian byte sequence.
    // Hint: this is used for certificate lifetime fields.
    //DONE?
    if (bytes==NULL || nbytes == 0 || nbytes>8) {
        return 0;
    }
    uint64_t result=0;
    for (int i=0; i<nbytes; i++) {
        result+=bytes[i]<<(8*(nbytes-i-1));
    }
    return result;
}

static bool parse_lifetime_window(const tlv* life, uint64_t* start_ts, uint64_t* end_ts) {
    // TODO: decode [not_before || not_after] from CERTIFICATE/LIFETIME.
    // Return false on malformed input (NULL pointers, wrong length, invalid range).
    //DONE?
    if (!life || !start_ts || !end_ts) {
        return false;
    }
    *start_ts = read_be_uint(life->val, 8);
    *end_ts = read_be_uint(life->val+8, 8);
    if (*start_ts>*end_ts) 
        return false;
    return true;
}

static void enforce_lifetime_valid(const tlv* life) {
    UNUSED(life);
    // TODO: enforce lifetime validity against current time.
    // Exit with code 1 for invalid/expired cert, code 6 for malformed time inputs.
    //DONE?
    uint64_t start;
    uint64_t end;
    if (!parse_lifetime_window(life, &start, &end)) {
        exit(6);
    }
    uint64_t curr = (uint64_t) time(NULL);
    if (curr<start || curr>end) {
        exit(1);
    }
}

void init_sec(int initial_state, char* peer_host, bool bad_mac) {
    state_sec = initial_state;
    hostname = peer_host;
    inc_mac = bad_mac;
    init_io();

    // TODO: initialize keys and role-specific state.
    //DONE?
    generate_private_key();
    derive_public_key();
    // Client side: load CA public key and prepare ephemeral keypair.
    // Server side: load certificate and prepare ephemeral keypair.
    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        load_ca_public_key("ca_public_key.bin");

        client_hello = create_tlv(CLIENT_HELLO);

        tlv *v = create_tlv(VERSION_TAG);
        uint8_t version = PROTOCOL_VERSION;
        add_val(v,&version, 1);
        add_tlv(client_hello, v);

        tlv* nonce = create_tlv(NONCE);
        uint8_t randBuffer[NONCE_SIZE];
        generate_nonce(randBuffer, NONCE_SIZE);
        add_val(nonce, randBuffer, NONCE_SIZE);
        add_tlv(client_hello, nonce);

        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, (uint16_t)pub_key_size);
        add_tlv(client_hello,pk);

    }
    else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        load_certificate("server_cert.bin");
    }

}

ssize_t input_sec(uint8_t* out_buf, size_t out_cap) {
    switch ( state_sec ) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        // TODO: build CLIENT_HELLO with VERSION_TAG, NONCE, and PUBLIC_KEY TLVs.
        // Save client nonce for later key derivation and advance to CLIENT_SERVER_HELLO_AWAIT.
        ssize_t len = serialize_tlv(out_buf, client_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        // TODO: build SERVER_HELLO with NONCE, CERTIFICATE, PUBLIC_KEY, HANDSHAKE_SIGNATURE.
        // Sign the expected handshake transcript, derive session keys, then enter DATA_STATE.
        server_hello = create_tlv(SERVER_HELLO);
         
        tlv* nonce = create_tlv(NONCE);
        uint8_t randbuf[NONCE_SIZE];
        generate_nonce(randbuf, NONCE_SIZE);
        add_val(nonce, randbuf, NONCE_SIZE);
        add_tlv(server_hello, nonce);

        tlv* cert=deserialize_tlv(certificate, (uint16_t)cert_size);
        add_tlv(server_hello, cert);

        tlv *pk = create_tlv(PUBLIC_KEY);
        add_val(pk,public_key,(uint16_t)pub_key_size);
        add_tlv(server_hello, pk);

        uint8_t history[5000];
        uint16_t historyLen=0;
        historyLen+=serialize_tlv(history+historyLen,client_hello);
        historyLen+=serialize_tlv(history+historyLen,nonce);
        historyLen+=serialize_tlv(history+historyLen,pk);

        EVP_PKEY* ephem = get_private_key();
        load_private_key("server_key.bin");
        uint8_t sign_buf[255];
        size_t sign_len = sign(sign_buf, history, historyLen);
        set_private_key(ephem);

        tlv* sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig_tlv, sign_buf, (uint16_t) sign_len);
        add_tlv(server_hello, sig_tlv);

        derive_secret();
        uint8_t salt[NONCE_SIZE*2];
        tlv* cn = get_tlv(client_hello, NONCE);
        if (cn) {
             memcpy(salt,cn->val,NONCE_SIZE);
        }
        memcpy(salt+NONCE_SIZE, randbuf, NONCE_SIZE);
        derive_keys(salt, 64);


        ssize_t len=serialize_tlv(outbuf, server_hello);
        state_sec=DATA_STATE;
        return len;
    }
    case DATA_STATE: {
        uint8_t in_buf[2048];
        ssize_t in_len = input_io(in_buf,sizeof(in_buf));
        if (in_len<=0) return 0;

        uint8_t iv_buf[IV_SIZE];
        uint8_t cipher_buf[4096];
        size_t cipher_len=encrypt_data(iv_buf,cipher_buf,in_buf,in_len);

        tlv* data_tlv=create_tlv(DATA);
        tlv* iv_tlv=create_tlv(IV);
        add_val(iv_tlv, iv_buf, IV_SIZE);
        add_tlv(data_tlv, iv_tlv);

        tlv* c_tlv=create_tlv(CIPHERTEXT);
        add_val(c_tlv,cipher_buf,(uint16_t) cipher_len);
        
        uint8_t to_mac[4096];
        uint16_t m_len = 0;
        m_len+=serialize_tlv(to_mac+m_len,iv_tlv);
        m_len+=serialize_tlv(to_mac+m_len,c_tlv);

        uint8_t mac_buf[MAC_SIZE];
        hmac(mac_buf,to_mac,m_len);

        if (inc_mac) mac_buf[0] ^= 0xFF; 
        tlv* mac_tlv=create_tlv(MAC);
        add_val(mac_tlv,mac_buf,MAC_SIZE);
        add_tlv(data_tlv,mac_tlv);
        add_tlv(data_tlv,c_tlv);

        ssize_t len=serialize_tlv(out_buf,data_tlv);
        free_tlv(data_tlv);
        return len;
    }
    default:
        // TODO: handle unexpected states.
        return (ssize_t) 0;
    }
}

void output_sec(uint8_t* in_buf, size_t in_len) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        print("RECV CLIENT HELLO");
        client_hello = deserialize_tlv(in_buf,(uint16_t) in_len);
        if (client_hello == NULL || client_hello->type!=CLIENT_HELLO) 
            exit(6);

        tlv *v = get_tlv(client_hello,VERSION_TAG);
        if (v==NULL || v->length!=1 || v->val[0]!=PROTOCOL_VERSION) 
            exit(6);

        tlv *n = get_tlv(client_hello,NONCE);
        if (n==NULL || n->length!=NONCE_SIZE)
            exit(6);
        
        memcpy(client_nonce_buf, n->val, NONCE_SIZE);

        tlv *pk = get_tlv(client_hello, PUBLIC_KEY);
        if (pk==NULL) exit(6);

        load_peer_public_key(pk->val, pk->length);

        state_sec=SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");
        server_hello = deserialize_tlv(in_buf, (uint16_t) in_len);

        if (server_hello==NULL || server_hello->type!=SERVER_HELLO)
            exit(6);
        
        tlv *cert = get_tlv(server_hello, CERTIFICATE);
        if (cert==NULL)
            exit(6);

        tlv* cert_sign = get_tlv(cert,SIGNATURE);
        if (cert_sign==NULL)
            exit(6);

        tlv* dns=get_tlv(cert,DNS_NAME);
        tlv* life=get_tlv(cert, LIFETIME);
        tlv* cert_pk=get_tlv(cert, PUBLIC_KEY);
        if (dns==NULL || life==NULL || cert_pk==NULL) 
            exit(6);

        uint8_t cert_to_sign[4096];
        uint16_t c_len=0;
        c_len+=serialize_tlv(cert_to_sign, dns);
        c_len+=serialize_tlv(cert_to_sign+c_len, cert_pk);
        c_len+=serialize_tlv(cert_to_sign+c_len, life);

        if (verify(cert_sign->val, cert_sign->length, cert_to_sign, c_len, ec_ca_public_key) != 1)
            exit(1);

        if (hostname!=NULL) {
            size_t h_len=strlen(hostname);
            bool match=false;
            if (dns->length==h_len && memcmp(dns->val,hostname,h_len)==0) {
                match=true;
            }
            else if (dns->length==h_len+1 && memcmp(dns->val,hostname,h_len)==0) {
                match=true;
            }
            else if (dns->length>h_len && memcmp(dns->val,hostname,h_len)==0 && dns->val[h_len]=='\0') {
                match=true;
            }
            if (!match) exit(2);
        }

        enforce_lifetime_valid(life);

        tlv* n=get_tlv(server_hello, NONCE);
        if (n==NULL || n->length!=NONCE_SIZE) 
            exit(6);
        memcpy(server_nonce_buf,n->val, NONCE_SIZE);

        tlv* pk=get_tlv(server_hello, PUBLIC_KEY);
        if (pk==NULL) exit(6);

        tlv* hs_sign=get_tlv(server_hello,HANDSHAKE_SIGNATURE);
        if (hs_sign==NULL)
            exit(6);

        uint8_t transcript[4096];
        uint16_t t_len=0;
        t_len+=serialize_tlv(transcript,client_hello);
        t_len+=serialize_tlv(transcript+t_len,n);
        t_len+=serialize_tlv(transcript+t_len,pk);

        load_peer_public_key(cert_pk->val, cert_pk->length);
        if (verify(hs_sign->val, hs_sign->length, transcript, t_len, ec_peer_public_key)!=1)
            exit(3);
        
        load_peer_public_key(pk->val, pk->length);
        derive_secret();
        uint8_t salt[NONCE_SIZE*2];
        memcpy(salt, client_nonce_buf, NONCE_SIZE);
        memcpy(salt+NONCE_SIZE, server_nonce_buf, NONCE_SIZE);
        derive_keys(salt,64);

        state_sec=DATA_STATE;

        // TODO: parse SERVER_HELLO and verify certificate chain/lifetime/hostname.
        // Verify handshake signature, load server ephemeral key, derive keys, enter DATA_STATE.
        // Required exit codes: bad cert(1), bad identity(2), bad handshake sig(3), malformed(6).
        break;
    }
    case DATA_STATE: {
        // TODO: parse DATA, verify MAC before decrypting, then output plaintext.
        // Required exit code: bad MAC(5), malformed(6).
        tlv *data_tlv = deserialize_tlv(in_buf, (uint16_t)in_len);
        if (data_tlv == NULL || data_tlv->type != DATA)
            exit(6);

        tlv *iv_tlv = get_tlv(data_tlv, IV);
        tlv *mac_tlv = get_tlv(data_tlv, MAC);
        tlv *c_tlv = get_tlv(data_tlv, CIPHERTEXT);
        if (!iv_tlv || !mac_tlv || !c_tlv)
            exit(6);

        uint8_t to_mac[4096];
        uint16_t m_len = 0;
        m_len+=serialize_tlv(to_mac, iv_tlv);
        m_len+=serialize_tlv(to_mac + m_len, c_tlv);

        uint8_t mac_buf[MAC_SIZE];
        hmac(mac_buf, to_mac, m_len);
        if (memcmp(mac_buf, mac_tlv->val, MAC_SIZE) != 0)
            exit(5);

        uint8_t plain_buf[4096];
        size_t plain_len=decrypt_cipher(plain_buf, c_tlv->val, c_tlv->length, iv_tlv->val);
        output_io(plain_buf, plain_len);
        free_tlv(data_tlv);
        break;
    }
    default:
        // TODO: handle unexpected states.
        break;
    }
}
