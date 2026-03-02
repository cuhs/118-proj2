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
    if (bytes==NULL || nbytes == 0 || nbytes>8) [
        return 0;
    ]
    uint64_t result;
    for (int i=0; i<nbytes; i++) {
        result+=bytes[i]<<(8*(nybtes-i-1));
    }
    return result;
}

static bool parse_lifetime_window(const tlv* life, uint64_t* start_ts, uint64_t* end_ts) {
    UNUSED(life);
    UNUSED(start_ts);
    UNUSED(end_ts);
    // TODO: decode [not_before || not_after] from CERTIFICATE/LIFETIME.
    // Return false on malformed input (NULL pointers, wrong length, invalid range).
    //DONE?
    if (!life || !start_ts || !end_ts) {
        return false;
    }
    *start_ts = read_be_uint(life->val, 8);
    *end_ts = read_be_unit(life->val+8, 8);
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
    if (!parse_lifetime_window(life, &start, &end);) {
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
        ssize_t len = serialize_tlv(out,buf, client_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        // TODO: build SERVER_HELLO with NONCE, CERTIFICATE, PUBLIC_KEY, HANDSHAKE_SIGNATURE.
        // Sign the expected handshake transcript, derive session keys, then enter DATA_STATE.
        server_hello = create_tlv(SERVER_HELLO);
         
        tlv* nonce = create_tlv(NONCE);
        uint8_t randbuf;
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


        ssize_t len=seralize_tlv(outbuf, server_hello);
        state_sec=DATA_STATE;
        return len;
    }
    case DATA_STATE: {
        UNUSED(out_buf);
        UNUSED(out_cap);
        // TODO: read plaintext from stdin, encrypt it, compute MAC, serialize DATA TLV.
        // If `inc_mac` is true, intentionally corrupt the MAC for testing.
        return (ssize_t) 0;
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
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse CLIENT_HELLO, validate required fields and protocol version.
        // Load peer ephemeral key, store client nonce, and transition to SERVER_SERVER_HELLO_SEND.
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse SERVER_HELLO and verify certificate chain/lifetime/hostname.
        // Verify handshake signature, load server ephemeral key, derive keys, enter DATA_STATE.
        // Required exit codes: bad cert(1), bad identity(2), bad handshake sig(3), malformed(6).
        break;
    }
    case DATA_STATE: {
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse DATA, verify MAC before decrypting, then output plaintext.
        // Required exit code: bad MAC(5), malformed(6).
        break;
    }
    default:
        // TODO: handle unexpected states.
        break;
    }
}
