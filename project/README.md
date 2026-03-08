# CS 118 Project 2

Name: Alex Hu

This project implements a secure transport layer protocol on top of TCP using OpenSSL for the cryptographic primitives. The core logic is located in `security.c`, where I built a state machine to manage the 1-RTT handshake between the client and server.

During the handshake, the client and server generate ephemeral ECDH keys to derive a shared session secret. The server's identity is verified by validating a CA-signed certificate, which includes checking the signature, the DNS name against the expected hostname, and the validity lifetime window. One of the trickier parts of the implementation was properly serializing and deserializing the nested TLV structures, especially gathering the handshake transcript to verify the server's signature and prevent man-in-the-middle attacks.

Once the handshake completes, the connection moves into the data state. For the secure data transfer, I used AES-256-CBC to encrypt the application data with a randomly generated 16-byte IV for each packet. To guarantee integrity, the protocol uses an encrypt-then-MAC approach, computing an HMAC-SHA256 over the serialized IV and ciphertext. This ensures that the application data remains completely private and tamper-proof across the network.
