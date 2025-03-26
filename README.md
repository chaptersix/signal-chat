
# Encrypted Chat Application with gRPC

**⚠️ Important: This project is a proof-of-concept and is *not suitable for production use*. It lacks critical security features such as forward secrecy, robust client authentication, and scalable key management. See the "Security Considerations" section for details.**

## Project Overview

This project is a simple chat application built using gRPC, featuring two Go clients that communicate through a central server. The standout feature is **end-to-end encryption** of messages, ensuring that only the intended recipients can read them. The encryption scheme is inspired by the Signal protocol but implements a simplified hybrid encryption approach suitable for group chats.

### Features
- **End-to-End Encryption**: Messages are encrypted on the client side and remain encrypted on the server.
- **Group Chat**: Messages are broadcast to all connected clients.
- **gRPC-Based Communication**: Leverages Protocol Buffers for efficient and scalable communication.

---

## Architecture

The application follows a straightforward client-server architecture:

- **Server**: A Go-based gRPC server responsible for managing client connections, storing public keys (in memory), and relaying encrypted messages. It cannot decrypt messages.
- **Clients**: Go applications that connect to the server, register their public keys, send encrypted messages, and receive and decrypt messages from others.

### Encryption Protocol

The encryption protocol combines symmetric and asymmetric cryptography in a hybrid system:

1. **Key Generation**:
   - Each client generates an ECDSA key pair using the P-256 elliptic curve for identity and encryption purposes.

2. **Public Key Registration**:
   - Upon connecting, clients register their public keys with the server.

3. **Message Encryption**:
   - When a client sends a message:
     - It generates a random 256-bit symmetric key (AES-256).
     - The message is encrypted with this symmetric key using AES-GCM (Galois/Counter Mode).
     - For each recipient, the client:
       - Generates an ephemeral ECDSA key pair.
       - Computes a shared secret using ECDH (Elliptic Curve Diffie-Hellman) with the recipient’s public key and the ephemeral private key.
       - Encrypts the symmetric key with the shared secret using AES-GCM.
     - The encrypted message and a map of encrypted symmetric keys (one per recipient) are sent to the server.

4. **Message Relaying**:
   - The server broadcasts the encrypted message and the associated encrypted symmetric keys to all connected clients without accessing the plaintext.

5. **Message Decryption**:
   - Each receiving client:
     - Uses its private key and the sender’s ephemeral public key to compute the shared secret via ECDH.
     - Decrypts its corresponding encrypted symmetric key with the shared secret.
     - Decrypts the message using the symmetric key and displays it.

This ensures that only the intended recipients can decrypt the message, and the server remains oblivious to the plaintext content.

---

## Setup Instructions

### Prerequisites
- **Go**: Version 1.21 or later.
- **protoc**: The Protocol Buffers compiler for generating gRPC code.
- **Go Plugins for protoc**: Install `protoc-gen-go` and `protoc-gen-go-grpc` with:
  ```bash
  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
  ```

### Installation
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:
   ```bash
   go mod tidy
   ```

3. **Generate gRPC Code**:
   Compile the `.proto` file to generate Go code:
   ```bash
   protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/chat.proto
   ```

### Running the Application
1. **Start the Server**:
   ```bash
   go run server/main.go
   ```

2. **Run Clients** (in separate terminals):
   Launch each client with a unique ID:
   ```bash
   go run client/main.go client1
   go run client/main.go client2
   ```

---

## Usage

- **Startup**: Each client registers its public key with the server upon connecting.
- **Sending Messages**: Type a message in a client terminal and press Enter to send it. The message is encrypted and broadcast to all clients.
- **Receiving Messages**: Each client decrypts incoming messages using its private key and displays them in the terminal.

---

## Encryption Details

Here’s a deeper look at the encryption process, complete with code samples.

### Key Generation

Each client generates an ECDSA key pair using the P-256 curve:

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "log"
)

privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
    log.Fatalf("Failed to generate key: %v", err)
}
publicKey := &privateKey.PublicKey
```

The public key is serialized and registered with the server:

```go
keyBytes := elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)
_, err = client.RegisterPublicKey(context.Background(), &pb.RegisterPublicKeyRequest{
    ClientId: clientID,
    Key:      keyBytes,
})
if err != nil {
    log.Fatalf("Failed to register public key: %v", err)
}
```

### Message Encryption

When sending a message, the client follows these steps:

1. **Generate a Symmetric Key**:
   ```go
   symmetricKey := make([]byte, 32) // 256-bit key for AES-256
   _, err = rand.Read(symmetricKey)
   if err != nil {
       log.Fatalf("Failed to generate symmetric key: %v", err)
   }
   ```

2. **Encrypt the Message with AES-GCM**:
   ```go
   import (
       "crypto/aes"
       "crypto/cipher"
   )

   block, err := aes.NewCipher(symmetricKey)
   if err != nil {
       log.Fatalf("Failed to create AES cipher: %v", err)
   }
   gcm, err := cipher.NewGCM(block)
   if err != nil {
       log.Fatalf("Failed to create GCM: %v", err)
   }
   nonce := make([]byte, gcm.NonceSize())
   _, err = rand.Read(nonce)
   if err != nil {
       log.Fatalf("Failed to generate nonce: %v", err)
   }
   ciphertext := gcm.Seal(nil, nonce, []byte(messageContent), nil)
   ```

3. **Encrypt the Symmetric Key for Each Recipient**:
   For each recipient, the client generates an ephemeral key pair and encrypts the symmetric key:
   ```go
   ephemPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
   if err != nil {
       log.Fatalf("Failed to generate ephemeral key: %v", err)
   }
   ephemPub := &ephemPriv.PublicKey

   // Compute shared secret using ECDH
   sharedX, _ := recipientPub.Curve.ScalarMult(recipientPub.X, recipientPub.Y, ephemPriv.D.Bytes())
   sharedKey := sharedX.Bytes()

   block, err = aes.NewCipher(sharedKey)
   if err != nil {
       log.Fatalf("Failed to create AES cipher for shared key: %v", err)
   }
   gcm, err = cipher.NewGCM(block)
   if err != nil {
       log.Fatalf("Failed to create GCM for shared key: %v", err)
   }
   nonce = make([]byte, gcm.NonceSize())
   _, err = rand.Read(nonce)
   if err != nil {
       log.Fatalf("Failed to generate nonce: %v", err)
   }
   encryptedSymKey := gcm.Seal(nil, nonce, symmetricKey, nil)
   ```

4. **Send to Server**: The client sends the encrypted message and a map of encrypted symmetric keys (keyed by recipient ID) to the server.

### Message Decryption

When a client receives a message:

1. **Compute the Shared Secret**:
   Using its private key and the sender’s ephemeral public key:
   ```go
   sharedX, _ := privateKey.Curve.ScalarMult(ephemPub.X, ephemPub.Y, privateKey.D.Bytes())
   sharedKey := sharedX.Bytes()
   ```

2. **Decrypt the Symmetric Key**:
   ```go
   block, err := aes.NewCipher(sharedKey)
   if err != nil {
       log.Fatalf("Failed to create AES cipher: %v", err)
   }
   gcm, err := cipher.NewGCM(block)
   if err != nil {
       log.Fatalf("Failed to create GCM: %v", err)
   }
   symKey, err := gcm.Open(nil, encryptedKey.Nonce, encryptedKey.Ciphertext, nil)
   if err != nil {
       log.Fatalf("Failed to decrypt symmetric key: %v", err)
   }
   ```

3. **Decrypt the Message**:
   ```go
   block, err = aes.NewCipher(symKey)
   if err != nil {
       log.Fatalf("Failed to create AES cipher: %v", err)
   }
   gcm, err = cipher.NewGCM(block)
   if err != nil {
       log.Fatalf("Failed to create GCM: %v", err)
   }
   plaintext, err := gcm.Open(nil, msg.EncryptedMessage.Nonce, msg.EncryptedMessage.Ciphertext, nil)
   if err != nil {
       log.Fatalf("Failed to decrypt message: %v", err)
   }
   fmt.Println("Received message:", string(plaintext))
   ```

---

## Security Considerations

**⚠️ This project is *not ready for production by a long shot*.** While it demonstrates end-to-end encryption, it lacks several critical security features:

- **No Forward Secrecy**: If a client’s private key is compromised, all past messages can be decrypted. The full Signal protocol uses ratcheting (e.g., Double Ratchet) to ensure past messages remain secure even if keys are exposed.
- **No Client Authentication**: Clients are identified only by their self-reported IDs and public keys. There’s no mechanism to verify identities, making impersonation possible.
- **Insecure Key Management**: Public keys are stored in memory on the server, which is neither persistent nor secure. Production systems require robust key storage (e.g., encrypted databases).
- **Scalability Limitations**: Encrypting the symmetric key for each recipient individually scales poorly with group size, increasing message size linearly. Advanced protocols like Signal’s Sender Key or MLS (Messaging Layer Security) are more efficient.
- **Weak Error Handling**: Cryptographic operations have basic error handling, insufficient for detecting or mitigating attacks in production.
- **Unprotected Metadata**: While message content is encrypted and authenticated, metadata (e.g., sender ID) is not, allowing potential tampering.

---

## Future Improvements

To make this project more secure and production-ready, consider:

- **Full Signal Protocol**: Implement the Double Ratchet for one-to-one chats and Sender Key for group chats to ensure forward secrecy and scalability.
- **Client Authentication**: Add certificate-based authentication or a trusted authority to verify client identities.
- **Secure Key Storage**: Use a persistent, encrypted database or key management service for public keys.
- **Efficient Group Encryption**: Adopt Sender Key or MLS for better performance in large groups.
- **Robust Error Handling**: Enhance error detection and logging for cryptographic operations.
- **Metadata Protection**: Authenticate all message components, including metadata, to prevent tampering.

---

This README provides a comprehensive guide to understanding, setting up, and running the project, along with detailed insights into its encryption protocol. However, its significant security limitations mean it should only be used for educational purposes, not real-world communication.
