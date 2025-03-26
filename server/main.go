package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	pb "github.com/chaptersix/signal-chat/proto"
	"google.golang.org/grpc"
)

type chatServer struct {
	pb.UnimplementedChatServiceServer
	mu         sync.Mutex
	clients    map[string]chan *pb.Message
	publicKeys map[string]*pb.PublicKey
}

func NewChatServer() *chatServer {
	return &chatServer{
		clients:    make(map[string]chan *pb.Message),
		publicKeys: make(map[string]*pb.PublicKey),
	}
}

func (s *chatServer) RegisterPublicKey(ctx context.Context, req *pb.RegisterPublicKeyRequest) (*pb.RegisterPublicKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicKeys[req.ClientId] = &pb.PublicKey{
		ClientId: req.ClientId,
		Key:      req.Key,
	}
	return &pb.RegisterPublicKeyResponse{}, nil
}

func (s *chatServer) GetPublicKeys(ctx context.Context, req *pb.GetPublicKeysRequest) (*pb.GetPublicKeysResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var publicKeys []*pb.PublicKey
	for _, pk := range s.publicKeys {
		publicKeys = append(publicKeys, pk)
	}
	return &pb.GetPublicKeysResponse{PublicKeys: publicKeys}, nil
}

func (s *chatServer) GetConnectedClients(ctx context.Context, req *pb.GetConnectedClientsRequest) (*pb.GetConnectedClientsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var clientIds []string
	for clientId := range s.clients {
		clientIds = append(clientIds, clientId)
	}
	return &pb.GetConnectedClientsResponse{ClientIds: clientIds}, nil
}

func (s *chatServer) SendMessage(ctx context.Context, req *pb.MessageRequest) (*pb.MessageResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg := &pb.Message{
		Sender:           req.Sender,
		EncryptedMessage: req.EncryptedMessage,
		EncryptedKeys:    req.EncryptedKeys,
		Timestamp:        time.Now().Unix(),
	}

	for _, ch := range s.clients {
		select {
		case ch <- msg:
		default:
			// Skip if channel is full to avoid blocking
		}
	}
	return &pb.MessageResponse{Success: true}, nil
}

func (s *chatServer) ReceiveMessages(stream pb.ChatService_ReceiveMessagesServer) error {
	var clientID string

	// Initial client registration
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	clientID = req.ClientId

	msgChan := make(chan *pb.Message, 10)
	s.mu.Lock()
	s.clients[clientID] = msgChan
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()
		close(msgChan)
		log.Printf("Client %s disconnected", clientID)
	}()

	// Send messages to the client
	go func() {
		for msg := range msgChan {
			if err := stream.Send(msg); err != nil {
				log.Printf("Error sending to %s: %v", clientID, err)
				return
			}
		}
	}()

	// Keep the stream alive
	for {
		_, err := stream.Recv()
		if err != nil {
			log.Printf("Stream closed for %s: %v", clientID, err)
			return err
		}
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterChatServiceServer(s, NewChatServer())
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

