// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: proto/chat.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PublicKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ClientId      string                 `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Key           []byte                 `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"` // Marshaled ECDSA public key (uncompressed format)
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PublicKey) Reset() {
	*x = PublicKey{}
	mi := &file_proto_chat_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKey) ProtoMessage() {}

func (x *PublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKey.ProtoReflect.Descriptor instead.
func (*PublicKey) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{0}
}

func (x *PublicKey) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *PublicKey) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

type EncryptedKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	SEphemKey     []byte                 `protobuf:"bytes,1,opt,name=s_ephem_key,json=sEphemKey,proto3" json:"s_ephem_key,omitempty"` // Marshaled ephemeral public key
	Nonce         []byte                 `protobuf:"bytes,2,opt,name=nonce,proto3" json:"nonce,omitempty"`
	Ciphertext    []byte                 `protobuf:"bytes,3,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"` // Encrypted symmetric key
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EncryptedKey) Reset() {
	*x = EncryptedKey{}
	mi := &file_proto_chat_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EncryptedKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptedKey) ProtoMessage() {}

func (x *EncryptedKey) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptedKey.ProtoReflect.Descriptor instead.
func (*EncryptedKey) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{1}
}

func (x *EncryptedKey) GetSEphemKey() []byte {
	if x != nil {
		return x.SEphemKey
	}
	return nil
}

func (x *EncryptedKey) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *EncryptedKey) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

type EncryptedMessage struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Nonce         []byte                 `protobuf:"bytes,1,opt,name=nonce,proto3" json:"nonce,omitempty"`
	Ciphertext    []byte                 `protobuf:"bytes,2,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"` // Encrypted message content
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EncryptedMessage) Reset() {
	*x = EncryptedMessage{}
	mi := &file_proto_chat_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EncryptedMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptedMessage) ProtoMessage() {}

func (x *EncryptedMessage) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptedMessage.ProtoReflect.Descriptor instead.
func (*EncryptedMessage) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{2}
}

func (x *EncryptedMessage) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *EncryptedMessage) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

type MessageRequest struct {
	state            protoimpl.MessageState   `protogen:"open.v1"`
	Sender           string                   `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	EncryptedMessage *EncryptedMessage        `protobuf:"bytes,2,opt,name=encrypted_message,json=encryptedMessage,proto3" json:"encrypted_message,omitempty"`
	EncryptedKeys    map[string]*EncryptedKey `protobuf:"bytes,3,rep,name=encrypted_keys,json=encryptedKeys,proto3" json:"encrypted_keys,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *MessageRequest) Reset() {
	*x = MessageRequest{}
	mi := &file_proto_chat_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MessageRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageRequest) ProtoMessage() {}

func (x *MessageRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageRequest.ProtoReflect.Descriptor instead.
func (*MessageRequest) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{3}
}

func (x *MessageRequest) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

func (x *MessageRequest) GetEncryptedMessage() *EncryptedMessage {
	if x != nil {
		return x.EncryptedMessage
	}
	return nil
}

func (x *MessageRequest) GetEncryptedKeys() map[string]*EncryptedKey {
	if x != nil {
		return x.EncryptedKeys
	}
	return nil
}

type MessageResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Success       bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Error         string                 `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MessageResponse) Reset() {
	*x = MessageResponse{}
	mi := &file_proto_chat_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MessageResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageResponse) ProtoMessage() {}

func (x *MessageResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageResponse.ProtoReflect.Descriptor instead.
func (*MessageResponse) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{4}
}

func (x *MessageResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *MessageResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type ClientRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ClientId      string                 `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ClientRequest) Reset() {
	*x = ClientRequest{}
	mi := &file_proto_chat_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ClientRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientRequest) ProtoMessage() {}

func (x *ClientRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientRequest.ProtoReflect.Descriptor instead.
func (*ClientRequest) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{5}
}

func (x *ClientRequest) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

type Message struct {
	state            protoimpl.MessageState   `protogen:"open.v1"`
	Sender           string                   `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	EncryptedMessage *EncryptedMessage        `protobuf:"bytes,2,opt,name=encrypted_message,json=encryptedMessage,proto3" json:"encrypted_message,omitempty"`
	EncryptedKeys    map[string]*EncryptedKey `protobuf:"bytes,3,rep,name=encrypted_keys,json=encryptedKeys,proto3" json:"encrypted_keys,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Timestamp        int64                    `protobuf:"varint,4,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *Message) Reset() {
	*x = Message{}
	mi := &file_proto_chat_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{6}
}

func (x *Message) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

func (x *Message) GetEncryptedMessage() *EncryptedMessage {
	if x != nil {
		return x.EncryptedMessage
	}
	return nil
}

func (x *Message) GetEncryptedKeys() map[string]*EncryptedKey {
	if x != nil {
		return x.EncryptedKeys
	}
	return nil
}

func (x *Message) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

type RegisterPublicKeyRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ClientId      string                 `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Key           []byte                 `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RegisterPublicKeyRequest) Reset() {
	*x = RegisterPublicKeyRequest{}
	mi := &file_proto_chat_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegisterPublicKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterPublicKeyRequest) ProtoMessage() {}

func (x *RegisterPublicKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterPublicKeyRequest.ProtoReflect.Descriptor instead.
func (*RegisterPublicKeyRequest) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{7}
}

func (x *RegisterPublicKeyRequest) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *RegisterPublicKeyRequest) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

type RegisterPublicKeyResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RegisterPublicKeyResponse) Reset() {
	*x = RegisterPublicKeyResponse{}
	mi := &file_proto_chat_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegisterPublicKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterPublicKeyResponse) ProtoMessage() {}

func (x *RegisterPublicKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterPublicKeyResponse.ProtoReflect.Descriptor instead.
func (*RegisterPublicKeyResponse) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{8}
}

type GetPublicKeysRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPublicKeysRequest) Reset() {
	*x = GetPublicKeysRequest{}
	mi := &file_proto_chat_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPublicKeysRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPublicKeysRequest) ProtoMessage() {}

func (x *GetPublicKeysRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPublicKeysRequest.ProtoReflect.Descriptor instead.
func (*GetPublicKeysRequest) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{9}
}

type GetPublicKeysResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PublicKeys    []*PublicKey           `protobuf:"bytes,1,rep,name=public_keys,json=publicKeys,proto3" json:"public_keys,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetPublicKeysResponse) Reset() {
	*x = GetPublicKeysResponse{}
	mi := &file_proto_chat_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetPublicKeysResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetPublicKeysResponse) ProtoMessage() {}

func (x *GetPublicKeysResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetPublicKeysResponse.ProtoReflect.Descriptor instead.
func (*GetPublicKeysResponse) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{10}
}

func (x *GetPublicKeysResponse) GetPublicKeys() []*PublicKey {
	if x != nil {
		return x.PublicKeys
	}
	return nil
}

type GetConnectedClientsRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetConnectedClientsRequest) Reset() {
	*x = GetConnectedClientsRequest{}
	mi := &file_proto_chat_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetConnectedClientsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConnectedClientsRequest) ProtoMessage() {}

func (x *GetConnectedClientsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConnectedClientsRequest.ProtoReflect.Descriptor instead.
func (*GetConnectedClientsRequest) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{11}
}

type GetConnectedClientsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ClientIds     []string               `protobuf:"bytes,1,rep,name=client_ids,json=clientIds,proto3" json:"client_ids,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetConnectedClientsResponse) Reset() {
	*x = GetConnectedClientsResponse{}
	mi := &file_proto_chat_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetConnectedClientsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConnectedClientsResponse) ProtoMessage() {}

func (x *GetConnectedClientsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_chat_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConnectedClientsResponse.ProtoReflect.Descriptor instead.
func (*GetConnectedClientsResponse) Descriptor() ([]byte, []int) {
	return file_proto_chat_proto_rawDescGZIP(), []int{12}
}

func (x *GetConnectedClientsResponse) GetClientIds() []string {
	if x != nil {
		return x.ClientIds
	}
	return nil
}

var File_proto_chat_proto protoreflect.FileDescriptor

const file_proto_chat_proto_rawDesc = "" +
	"\n" +
	"\x10proto/chat.proto\x12\x04chat\":\n" +
	"\tPublicKey\x12\x1b\n" +
	"\tclient_id\x18\x01 \x01(\tR\bclientId\x12\x10\n" +
	"\x03key\x18\x02 \x01(\fR\x03key\"d\n" +
	"\fEncryptedKey\x12\x1e\n" +
	"\vs_ephem_key\x18\x01 \x01(\fR\tsEphemKey\x12\x14\n" +
	"\x05nonce\x18\x02 \x01(\fR\x05nonce\x12\x1e\n" +
	"\n" +
	"ciphertext\x18\x03 \x01(\fR\n" +
	"ciphertext\"H\n" +
	"\x10EncryptedMessage\x12\x14\n" +
	"\x05nonce\x18\x01 \x01(\fR\x05nonce\x12\x1e\n" +
	"\n" +
	"ciphertext\x18\x02 \x01(\fR\n" +
	"ciphertext\"\x93\x02\n" +
	"\x0eMessageRequest\x12\x16\n" +
	"\x06sender\x18\x01 \x01(\tR\x06sender\x12C\n" +
	"\x11encrypted_message\x18\x02 \x01(\v2\x16.chat.EncryptedMessageR\x10encryptedMessage\x12N\n" +
	"\x0eencrypted_keys\x18\x03 \x03(\v2'.chat.MessageRequest.EncryptedKeysEntryR\rencryptedKeys\x1aT\n" +
	"\x12EncryptedKeysEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12(\n" +
	"\x05value\x18\x02 \x01(\v2\x12.chat.EncryptedKeyR\x05value:\x028\x01\"A\n" +
	"\x0fMessageResponse\x12\x18\n" +
	"\asuccess\x18\x01 \x01(\bR\asuccess\x12\x14\n" +
	"\x05error\x18\x02 \x01(\tR\x05error\",\n" +
	"\rClientRequest\x12\x1b\n" +
	"\tclient_id\x18\x01 \x01(\tR\bclientId\"\xa3\x02\n" +
	"\aMessage\x12\x16\n" +
	"\x06sender\x18\x01 \x01(\tR\x06sender\x12C\n" +
	"\x11encrypted_message\x18\x02 \x01(\v2\x16.chat.EncryptedMessageR\x10encryptedMessage\x12G\n" +
	"\x0eencrypted_keys\x18\x03 \x03(\v2 .chat.Message.EncryptedKeysEntryR\rencryptedKeys\x12\x1c\n" +
	"\ttimestamp\x18\x04 \x01(\x03R\ttimestamp\x1aT\n" +
	"\x12EncryptedKeysEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12(\n" +
	"\x05value\x18\x02 \x01(\v2\x12.chat.EncryptedKeyR\x05value:\x028\x01\"I\n" +
	"\x18RegisterPublicKeyRequest\x12\x1b\n" +
	"\tclient_id\x18\x01 \x01(\tR\bclientId\x12\x10\n" +
	"\x03key\x18\x02 \x01(\fR\x03key\"\x1b\n" +
	"\x19RegisterPublicKeyResponse\"\x16\n" +
	"\x14GetPublicKeysRequest\"I\n" +
	"\x15GetPublicKeysResponse\x120\n" +
	"\vpublic_keys\x18\x01 \x03(\v2\x0f.chat.PublicKeyR\n" +
	"publicKeys\"\x1c\n" +
	"\x1aGetConnectedClientsRequest\"<\n" +
	"\x1bGetConnectedClientsResponse\x12\x1d\n" +
	"\n" +
	"client_ids\x18\x01 \x03(\tR\tclientIds2\x80\x03\n" +
	"\vChatService\x12T\n" +
	"\x11RegisterPublicKey\x12\x1e.chat.RegisterPublicKeyRequest\x1a\x1f.chat.RegisterPublicKeyResponse\x12H\n" +
	"\rGetPublicKeys\x12\x1a.chat.GetPublicKeysRequest\x1a\x1b.chat.GetPublicKeysResponse\x12Z\n" +
	"\x13GetConnectedClients\x12 .chat.GetConnectedClientsRequest\x1a!.chat.GetConnectedClientsResponse\x12:\n" +
	"\vSendMessage\x12\x14.chat.MessageRequest\x1a\x15.chat.MessageResponse\x129\n" +
	"\x0fReceiveMessages\x12\x13.chat.ClientRequest\x1a\r.chat.Message(\x010\x01B\tZ\a./protob\x06proto3"

var (
	file_proto_chat_proto_rawDescOnce sync.Once
	file_proto_chat_proto_rawDescData []byte
)

func file_proto_chat_proto_rawDescGZIP() []byte {
	file_proto_chat_proto_rawDescOnce.Do(func() {
		file_proto_chat_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_proto_chat_proto_rawDesc), len(file_proto_chat_proto_rawDesc)))
	})
	return file_proto_chat_proto_rawDescData
}

var file_proto_chat_proto_msgTypes = make([]protoimpl.MessageInfo, 15)
var file_proto_chat_proto_goTypes = []any{
	(*PublicKey)(nil),                   // 0: chat.PublicKey
	(*EncryptedKey)(nil),                // 1: chat.EncryptedKey
	(*EncryptedMessage)(nil),            // 2: chat.EncryptedMessage
	(*MessageRequest)(nil),              // 3: chat.MessageRequest
	(*MessageResponse)(nil),             // 4: chat.MessageResponse
	(*ClientRequest)(nil),               // 5: chat.ClientRequest
	(*Message)(nil),                     // 6: chat.Message
	(*RegisterPublicKeyRequest)(nil),    // 7: chat.RegisterPublicKeyRequest
	(*RegisterPublicKeyResponse)(nil),   // 8: chat.RegisterPublicKeyResponse
	(*GetPublicKeysRequest)(nil),        // 9: chat.GetPublicKeysRequest
	(*GetPublicKeysResponse)(nil),       // 10: chat.GetPublicKeysResponse
	(*GetConnectedClientsRequest)(nil),  // 11: chat.GetConnectedClientsRequest
	(*GetConnectedClientsResponse)(nil), // 12: chat.GetConnectedClientsResponse
	nil,                                 // 13: chat.MessageRequest.EncryptedKeysEntry
	nil,                                 // 14: chat.Message.EncryptedKeysEntry
}
var file_proto_chat_proto_depIdxs = []int32{
	2,  // 0: chat.MessageRequest.encrypted_message:type_name -> chat.EncryptedMessage
	13, // 1: chat.MessageRequest.encrypted_keys:type_name -> chat.MessageRequest.EncryptedKeysEntry
	2,  // 2: chat.Message.encrypted_message:type_name -> chat.EncryptedMessage
	14, // 3: chat.Message.encrypted_keys:type_name -> chat.Message.EncryptedKeysEntry
	0,  // 4: chat.GetPublicKeysResponse.public_keys:type_name -> chat.PublicKey
	1,  // 5: chat.MessageRequest.EncryptedKeysEntry.value:type_name -> chat.EncryptedKey
	1,  // 6: chat.Message.EncryptedKeysEntry.value:type_name -> chat.EncryptedKey
	7,  // 7: chat.ChatService.RegisterPublicKey:input_type -> chat.RegisterPublicKeyRequest
	9,  // 8: chat.ChatService.GetPublicKeys:input_type -> chat.GetPublicKeysRequest
	11, // 9: chat.ChatService.GetConnectedClients:input_type -> chat.GetConnectedClientsRequest
	3,  // 10: chat.ChatService.SendMessage:input_type -> chat.MessageRequest
	5,  // 11: chat.ChatService.ReceiveMessages:input_type -> chat.ClientRequest
	8,  // 12: chat.ChatService.RegisterPublicKey:output_type -> chat.RegisterPublicKeyResponse
	10, // 13: chat.ChatService.GetPublicKeys:output_type -> chat.GetPublicKeysResponse
	12, // 14: chat.ChatService.GetConnectedClients:output_type -> chat.GetConnectedClientsResponse
	4,  // 15: chat.ChatService.SendMessage:output_type -> chat.MessageResponse
	6,  // 16: chat.ChatService.ReceiveMessages:output_type -> chat.Message
	12, // [12:17] is the sub-list for method output_type
	7,  // [7:12] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_proto_chat_proto_init() }
func file_proto_chat_proto_init() {
	if File_proto_chat_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_proto_chat_proto_rawDesc), len(file_proto_chat_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   15,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_chat_proto_goTypes,
		DependencyIndexes: file_proto_chat_proto_depIdxs,
		MessageInfos:      file_proto_chat_proto_msgTypes,
	}.Build()
	File_proto_chat_proto = out.File
	file_proto_chat_proto_goTypes = nil
	file_proto_chat_proto_depIdxs = nil
}
