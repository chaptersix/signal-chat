package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	pb "github.com/chaptersix/signal-chat/proto"
	"google.golang.org/grpc"
)

func main() {
	// Connect to the gRPC server
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewChatServiceClient(conn)
	clientID := os.Args[1] // e.g., "client1" or "client2"

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Register public key with the server
	keyBytes := elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)
	_, err = client.RegisterPublicKey(context.Background(), &pb.RegisterPublicKeyRequest{
		ClientId: clientID,
		Key:      keyBytes,
	})
	if err != nil {
		log.Fatalf("failed to register public key: %v", err)
	}

	// Fetch all public keys from the server
	resp, err := client.GetPublicKeys(context.Background(), &pb.GetPublicKeysRequest{})
	if err != nil {
		log.Fatalf("failed to get public keys: %v", err)
	}
	publicKeysMap := make(map[string]*ecdsa.PublicKey)
	for _, pk := range resp.PublicKeys {
		x, y := elliptic.Unmarshal(elliptic.P256(), pk.Key)
		if x == nil {
			log.Printf("invalid public key for %s", pk.ClientId)
			continue
		}
		publicKeysMap[pk.ClientId] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
	}

	// Start receiving messages in a goroutine
	go func() {
		stream, err := client.ReceiveMessages(context.Background())
		if err != nil {
			log.Fatalf("error receiving messages: %v", err)
		}
		err = stream.Send(&pb.ClientRequest{ClientId: clientID})
		if err != nil {
			log.Fatalf("failed to send client ID: %v", err)
		}

		for {
			msg, err := stream.Recv()
			if err != nil {
				log.Printf("stream error: %v", err)
				return
			}

			// Decrypt the message
			encryptedKey, ok := msg.EncryptedKeys[clientID]
			if !ok {
				log.Printf("no encrypted key for %s", clientID)
				continue
			}

			// Deserialize ephemeral public key
			ephemX, ephemY := elliptic.Unmarshal(elliptic.P256(), encryptedKey.SEphemKey)
			if ephemX == nil {
				log.Printf("invalid ephemeral public key")
				continue
			}
			ephemPub := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     ephemX,
				Y:     ephemY,
			}

			// Compute shared secret
			sharedX, _ := privateKey.Curve.ScalarMult(ephemPub.X, ephemPub.Y, privateKey.D.Bytes())
			sharedKey := sharedX.Bytes()

			// Decrypt symmetric key
			block, err := aes.NewCipher(sharedKey)
			if err != nil {
				log.Printf("failed to create cipher: %v", err)
				continue
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				log.Printf("failed to create GCM: %v", err)
				continue
			}
			symKey, err := gcm.Open(nil, encryptedKey.Nonce, encryptedKey.Ciphertext, nil)
			if err != nil {
				log.Printf("failed to decrypt symmetric key: %v", err)
				continue
			}

			// Decrypt message content
			block, err = aes.NewCipher(symKey)
			if err != nil {
				log.Printf("failed to create cipher: %v", err)
				continue
			}
			gcm, err = cipher.NewGCM(block)
			if err != nil {
				log.Printf("failed to create GCM: %v", err)
				continue
			}
			plaintext, err := gcm.Open(nil, msg.EncryptedMessage.Nonce, msg.EncryptedMessage.Ciphertext, nil)
			if err != nil {
				log.Printf("failed to decrypt message: %v", err)
				continue
			}
			fmt.Printf("%s: %s\n", msg.Sender, string(plaintext))
		}
	}()

	// Send encrypted messages
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		content := scanner.Text()

		// Get list of connected clients
		connectedResp, err := client.GetConnectedClients(context.Background(), &pb.GetConnectedClientsRequest{})
		if err != nil {
			log.Printf("failed to get connected clients: %v", err)
			continue
		}
		connectedClientIds := connectedResp.ClientIds

		// Generate symmetric key
		symmetricKey := make([]byte, 32) // AES-256
		_, err = rand.Read(symmetricKey)
		if err != nil {
			log.Printf("failed to generate symmetric key: %v", err)
			continue
		}

		// Encrypt message content with symmetric key
		block, err := aes.NewCipher(symmetricKey)
		if err != nil {
			log.Printf("failed to create cipher: %v", err)
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			log.Printf("failed to create GCM: %v", err)
			continue
		}
		nonce := make([]byte, gcm.NonceSize())
		_, err = rand.Read(nonce)
		if err != nil {
			log.Printf("failed to generate nonce: %v", err)
			continue
		}
		ciphertext := gcm.Seal(nil, nonce, []byte(content), nil)
		encryptedMessage := &pb.EncryptedMessage{
			Nonce:      nonce,
			Ciphertext: ciphertext,
		}

		// Encrypt symmetric key for each connected client
		encryptedKeys := make(map[string]*pb.EncryptedKey)
		for _, recipientID := range connectedClientIds {
			recipientPub, ok := publicKeysMap[recipientID]
			if !ok {
				log.Printf("public key for %s not found", recipientID)
				continue
			}

			// Generate ephemeral key pair
			ephemPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				log.Printf("failed to generate ephemeral key: %v", err)
				continue
			}
			ephemPub := &ephemPriv.PublicKey

			// Compute shared secret with recipient's public key
			sharedX, _ := recipientPub.Curve.ScalarMult(recipientPub.X, recipientPub.Y, ephemPriv.D.Bytes())
			sharedKey := sharedX.Bytes()

			// Encrypt symmetric key with shared secret
			block, err := aes.NewCipher(sharedKey)
			if err != nil {
				log.Printf("failed to create cipher for %s: %v", recipientID, err)
				continue
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				log.Printf("failed to create GCM for %s: %v", recipientID, err)
				continue
			}
			nonce := make([]byte, gcm.NonceSize())
			_, err = rand.Read(nonce)
			if err != nil {
				log.Printf("failed to generate nonce for %s: %v", recipientID, err)
				continue
			}
			encryptedSymKey := gcm.Seal(nil, nonce, symmetricKey, nil)

			// Serialize ephemeral public key
			ephemKeyBytes := elliptic.Marshal(elliptic.P256(), ephemPub.X, ephemPub.Y)
			encryptedKeys[recipientID] = &pb.EncryptedKey{
				SEphemKey:  ephemKeyBytes,
				Nonce:      nonce,
				Ciphertext: encryptedSymKey,
			}
		}

		// Send the encrypted message
		_, err = client.SendMessage(context.Background(), &pb.MessageRequest{
			Sender:           clientID,
			EncryptedMessage: encryptedMessage,
			EncryptedKeys:    encryptedKeys,
		})
		if err != nil {
			log.Printf("could not send message: %v", err)
		}
	}
}

