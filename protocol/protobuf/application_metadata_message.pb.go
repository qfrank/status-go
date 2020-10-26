// Code generated by protoc-gen-go. DO NOT EDIT.
// source: application_metadata_message.proto

package protobuf

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ApplicationMetadataMessage_Type int32

const (
	ApplicationMetadataMessage_UNKNOWN                                 ApplicationMetadataMessage_Type = 0
	ApplicationMetadataMessage_CHAT_MESSAGE                            ApplicationMetadataMessage_Type = 1
	ApplicationMetadataMessage_CONTACT_UPDATE                          ApplicationMetadataMessage_Type = 2
	ApplicationMetadataMessage_MEMBERSHIP_UPDATE_MESSAGE               ApplicationMetadataMessage_Type = 3
	ApplicationMetadataMessage_PAIR_INSTALLATION                       ApplicationMetadataMessage_Type = 4
	ApplicationMetadataMessage_SYNC_INSTALLATION                       ApplicationMetadataMessage_Type = 5
	ApplicationMetadataMessage_REQUEST_ADDRESS_FOR_TRANSACTION         ApplicationMetadataMessage_Type = 6
	ApplicationMetadataMessage_ACCEPT_REQUEST_ADDRESS_FOR_TRANSACTION  ApplicationMetadataMessage_Type = 7
	ApplicationMetadataMessage_DECLINE_REQUEST_ADDRESS_FOR_TRANSACTION ApplicationMetadataMessage_Type = 8
	ApplicationMetadataMessage_REQUEST_TRANSACTION                     ApplicationMetadataMessage_Type = 9
	ApplicationMetadataMessage_SEND_TRANSACTION                        ApplicationMetadataMessage_Type = 10
	ApplicationMetadataMessage_DECLINE_REQUEST_TRANSACTION             ApplicationMetadataMessage_Type = 11
	ApplicationMetadataMessage_SYNC_INSTALLATION_CONTACT               ApplicationMetadataMessage_Type = 12
	ApplicationMetadataMessage_SYNC_INSTALLATION_ACCOUNT               ApplicationMetadataMessage_Type = 13
	ApplicationMetadataMessage_SYNC_INSTALLATION_PUBLIC_CHAT           ApplicationMetadataMessage_Type = 14
	ApplicationMetadataMessage_CONTACT_CODE_ADVERTISEMENT              ApplicationMetadataMessage_Type = 15
	ApplicationMetadataMessage_PUSH_NOTIFICATION_REGISTRATION          ApplicationMetadataMessage_Type = 16
	ApplicationMetadataMessage_PUSH_NOTIFICATION_REGISTRATION_RESPONSE ApplicationMetadataMessage_Type = 17
	ApplicationMetadataMessage_PUSH_NOTIFICATION_QUERY                 ApplicationMetadataMessage_Type = 18
	ApplicationMetadataMessage_PUSH_NOTIFICATION_QUERY_RESPONSE        ApplicationMetadataMessage_Type = 19
	ApplicationMetadataMessage_PUSH_NOTIFICATION_REQUEST               ApplicationMetadataMessage_Type = 20
	ApplicationMetadataMessage_PUSH_NOTIFICATION_RESPONSE              ApplicationMetadataMessage_Type = 21
	ApplicationMetadataMessage_EMOJI_REACTION                          ApplicationMetadataMessage_Type = 22
	ApplicationMetadataMessage_GROUP_CHAT_INVITATION                   ApplicationMetadataMessage_Type = 23
	ApplicationMetadataMessage_COMMUNITY_DESCRIPTION                ApplicationMetadataMessage_Type = 24
	ApplicationMetadataMessage_COMMUNITY_INVITATION                 ApplicationMetadataMessage_Type = 25
)

var ApplicationMetadataMessage_Type_name = map[int32]string{
	0:  "UNKNOWN",
	1:  "CHAT_MESSAGE",
	2:  "CONTACT_UPDATE",
	3:  "MEMBERSHIP_UPDATE_MESSAGE",
	4:  "PAIR_INSTALLATION",
	5:  "SYNC_INSTALLATION",
	6:  "REQUEST_ADDRESS_FOR_TRANSACTION",
	7:  "ACCEPT_REQUEST_ADDRESS_FOR_TRANSACTION",
	8:  "DECLINE_REQUEST_ADDRESS_FOR_TRANSACTION",
	9:  "REQUEST_TRANSACTION",
	10: "SEND_TRANSACTION",
	11: "DECLINE_REQUEST_TRANSACTION",
	12: "SYNC_INSTALLATION_CONTACT",
	13: "SYNC_INSTALLATION_ACCOUNT",
	14: "SYNC_INSTALLATION_PUBLIC_CHAT",
	15: "CONTACT_CODE_ADVERTISEMENT",
	16: "PUSH_NOTIFICATION_REGISTRATION",
	17: "PUSH_NOTIFICATION_REGISTRATION_RESPONSE",
	18: "PUSH_NOTIFICATION_QUERY",
	19: "PUSH_NOTIFICATION_QUERY_RESPONSE",
	20: "PUSH_NOTIFICATION_REQUEST",
	21: "PUSH_NOTIFICATION_RESPONSE",
	22: "EMOJI_REACTION",
	23: "GROUP_CHAT_INVITATION",
	24: "COMMUNITY_DESCRIPTION",
	25: "COMMUNITY_INVITATION",
}

var ApplicationMetadataMessage_Type_value = map[string]int32{
	"UNKNOWN":                                 0,
	"CHAT_MESSAGE":                            1,
	"CONTACT_UPDATE":                          2,
	"MEMBERSHIP_UPDATE_MESSAGE":               3,
	"PAIR_INSTALLATION":                       4,
	"SYNC_INSTALLATION":                       5,
	"REQUEST_ADDRESS_FOR_TRANSACTION":         6,
	"ACCEPT_REQUEST_ADDRESS_FOR_TRANSACTION":  7,
	"DECLINE_REQUEST_ADDRESS_FOR_TRANSACTION": 8,
	"REQUEST_TRANSACTION":                     9,
	"SEND_TRANSACTION":                        10,
	"DECLINE_REQUEST_TRANSACTION":             11,
	"SYNC_INSTALLATION_CONTACT":               12,
	"SYNC_INSTALLATION_ACCOUNT":               13,
	"SYNC_INSTALLATION_PUBLIC_CHAT":           14,
	"CONTACT_CODE_ADVERTISEMENT":              15,
	"PUSH_NOTIFICATION_REGISTRATION":          16,
	"PUSH_NOTIFICATION_REGISTRATION_RESPONSE": 17,
	"PUSH_NOTIFICATION_QUERY":                 18,
	"PUSH_NOTIFICATION_QUERY_RESPONSE":        19,
	"PUSH_NOTIFICATION_REQUEST":               20,
	"PUSH_NOTIFICATION_RESPONSE":              21,
	"EMOJI_REACTION":                          22,
	"GROUP_CHAT_INVITATION":                   23,
	"COMMUNITY_DESCRIPTION":                24,
	"COMMUNITY_INVITATION":                 25,
}

func (x ApplicationMetadataMessage_Type) String() string {
	return proto.EnumName(ApplicationMetadataMessage_Type_name, int32(x))
}

func (ApplicationMetadataMessage_Type) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ad09a6406fcf24c7, []int{0, 0}
}

type ApplicationMetadataMessage struct {
	// Signature of the payload field
	Signature []byte `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	// This is the encoded protobuf of the application level message, i.e ChatMessage
	Payload []byte `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	// The type of protobuf message sent
	Type                 ApplicationMetadataMessage_Type `protobuf:"varint,3,opt,name=type,proto3,enum=protobuf.ApplicationMetadataMessage_Type" json:"type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                        `json:"-"`
	XXX_unrecognized     []byte                          `json:"-"`
	XXX_sizecache        int32                           `json:"-"`
}

func (m *ApplicationMetadataMessage) Reset()         { *m = ApplicationMetadataMessage{} }
func (m *ApplicationMetadataMessage) String() string { return proto.CompactTextString(m) }
func (*ApplicationMetadataMessage) ProtoMessage()    {}
func (*ApplicationMetadataMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_ad09a6406fcf24c7, []int{0}
}

func (m *ApplicationMetadataMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ApplicationMetadataMessage.Unmarshal(m, b)
}
func (m *ApplicationMetadataMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ApplicationMetadataMessage.Marshal(b, m, deterministic)
}
func (m *ApplicationMetadataMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ApplicationMetadataMessage.Merge(m, src)
}
func (m *ApplicationMetadataMessage) XXX_Size() int {
	return xxx_messageInfo_ApplicationMetadataMessage.Size(m)
}
func (m *ApplicationMetadataMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_ApplicationMetadataMessage.DiscardUnknown(m)
}

var xxx_messageInfo_ApplicationMetadataMessage proto.InternalMessageInfo

func (m *ApplicationMetadataMessage) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *ApplicationMetadataMessage) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *ApplicationMetadataMessage) GetType() ApplicationMetadataMessage_Type {
	if m != nil {
		return m.Type
	}
	return ApplicationMetadataMessage_UNKNOWN
}

func init() {
	proto.RegisterEnum("protobuf.ApplicationMetadataMessage_Type", ApplicationMetadataMessage_Type_name, ApplicationMetadataMessage_Type_value)
	proto.RegisterType((*ApplicationMetadataMessage)(nil), "protobuf.ApplicationMetadataMessage")
}

func init() {
	proto.RegisterFile("application_metadata_message.proto", fileDescriptor_ad09a6406fcf24c7)
}

var fileDescriptor_ad09a6406fcf24c7 = []byte{
	// 514 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x53, 0x5d, 0x53, 0xda, 0x4c,
	0x14, 0x7e, 0x51, 0x5f, 0xd0, 0x23, 0xa5, 0xeb, 0x51, 0x4a, 0xf0, 0x93, 0xd2, 0x4e, 0x6b, 0xdb,
	0x19, 0x2e, 0xda, 0xeb, 0x5e, 0xac, 0x9b, 0x15, 0xb6, 0x25, 0x9b, 0xb8, 0xbb, 0xb1, 0xe3, 0xd5,
	0x4e, 0xac, 0xa9, 0xc3, 0x8c, 0x4a, 0x46, 0xe2, 0x05, 0x7f, 0xa3, 0xbf, 0xa2, 0x3f, 0xb3, 0x93,
	0x00, 0x05, 0x0a, 0xd6, 0xab, 0xcc, 0x3e, 0x1f, 0xe7, 0xcc, 0xf3, 0x6c, 0x16, 0x9a, 0x51, 0x92,
	0xdc, 0xf4, 0xbe, 0x47, 0x69, 0xaf, 0x7f, 0x67, 0x6f, 0xe3, 0x34, 0xba, 0x8a, 0xd2, 0xc8, 0xde,
	0xc6, 0x83, 0x41, 0x74, 0x1d, 0xb7, 0x92, 0xfb, 0x7e, 0xda, 0xc7, 0xf5, 0xfc, 0x73, 0xf9, 0xf0,
	0xa3, 0xf9, 0xab, 0x04, 0xbb, 0x74, 0x6a, 0xf0, 0xc6, 0x7a, 0x6f, 0x24, 0xc7, 0x7d, 0xd8, 0x18,
	0xf4, 0xae, 0xef, 0xa2, 0xf4, 0xe1, 0x3e, 0x76, 0x0a, 0x8d, 0xc2, 0x71, 0x59, 0x4d, 0x01, 0x74,
	0xa0, 0x94, 0x44, 0xc3, 0x9b, 0x7e, 0x74, 0xe5, 0xac, 0xe4, 0xdc, 0xe4, 0x88, 0x9f, 0x61, 0x2d,
	0x1d, 0x26, 0xb1, 0xb3, 0xda, 0x28, 0x1c, 0x57, 0x3e, 0xbe, 0x6b, 0x4d, 0xf6, 0xb5, 0x1e, 0xdf,
	0xd5, 0x32, 0xc3, 0x24, 0x56, 0xb9, 0xad, 0xf9, 0xb3, 0x08, 0x6b, 0xd9, 0x11, 0x37, 0xa1, 0x14,
	0xca, 0xaf, 0xd2, 0xff, 0x26, 0xc9, 0x7f, 0x48, 0xa0, 0xcc, 0x3a, 0xd4, 0x58, 0x8f, 0x6b, 0x4d,
	0xdb, 0x9c, 0x14, 0x10, 0xa1, 0xc2, 0x7c, 0x69, 0x28, 0x33, 0x36, 0x0c, 0x5c, 0x6a, 0x38, 0x59,
	0xc1, 0x03, 0xa8, 0x7b, 0xdc, 0x3b, 0xe1, 0x4a, 0x77, 0x44, 0x30, 0x86, 0xff, 0x58, 0x56, 0xb1,
	0x0a, 0x5b, 0x01, 0x15, 0xca, 0x0a, 0xa9, 0x0d, 0xed, 0x76, 0xa9, 0x11, 0xbe, 0x24, 0x6b, 0x19,
	0xac, 0x2f, 0x24, 0x9b, 0x87, 0xff, 0xc7, 0x57, 0x70, 0xa4, 0xf8, 0x59, 0xc8, 0xb5, 0xb1, 0xd4,
	0x75, 0x15, 0xd7, 0xda, 0x9e, 0xfa, 0xca, 0x1a, 0x45, 0xa5, 0xa6, 0x2c, 0x17, 0x15, 0xf1, 0x3d,
	0xbc, 0xa1, 0x8c, 0xf1, 0xc0, 0xd8, 0xa7, 0xb4, 0x25, 0xfc, 0x00, 0x6f, 0x5d, 0xce, 0xba, 0x42,
	0xf2, 0x27, 0xc5, 0xeb, 0x58, 0x83, 0xed, 0x89, 0x68, 0x96, 0xd8, 0xc0, 0x1d, 0x20, 0x9a, 0x4b,
	0x77, 0x0e, 0x05, 0x3c, 0x82, 0xbd, 0xbf, 0x67, 0xcf, 0x0a, 0x36, 0xb3, 0x6a, 0x16, 0x42, 0xda,
	0x71, 0x81, 0xa4, 0xbc, 0x9c, 0xa6, 0x8c, 0xf9, 0xa1, 0x34, 0xe4, 0x19, 0xbe, 0x84, 0x83, 0x45,
	0x3a, 0x08, 0x4f, 0xba, 0x82, 0xd9, 0xec, 0x5e, 0x48, 0x05, 0x0f, 0x61, 0x77, 0x72, 0x1f, 0xcc,
	0x77, 0xb9, 0xa5, 0xee, 0x39, 0x57, 0x46, 0x68, 0xee, 0x71, 0x69, 0xc8, 0x73, 0x6c, 0xc2, 0x61,
	0x10, 0xea, 0x8e, 0x95, 0xbe, 0x11, 0xa7, 0x82, 0x8d, 0x46, 0x28, 0xde, 0x16, 0xda, 0xa8, 0x51,
	0xe5, 0x24, 0x6b, 0xe8, 0xdf, 0x1a, 0xab, 0xb8, 0x0e, 0x7c, 0xa9, 0x39, 0xd9, 0xc2, 0x3d, 0xa8,
	0x2d, 0x8a, 0xcf, 0x42, 0xae, 0x2e, 0x08, 0xe2, 0x6b, 0x68, 0x3c, 0x42, 0x4e, 0x47, 0x6c, 0x67,
	0xa9, 0x97, 0xed, 0xcb, 0xfb, 0x23, 0x3b, 0x59, 0xa4, 0x65, 0xf4, 0xd8, 0x5e, 0xcd, 0x7e, 0x41,
	0xee, 0xf9, 0x5f, 0x84, 0x55, 0x7c, 0xdc, 0xf3, 0x0b, 0xac, 0x43, 0xb5, 0xad, 0xfc, 0x30, 0xc8,
	0x6b, 0xb1, 0x42, 0x9e, 0x0b, 0x33, 0x4a, 0x57, 0xc3, 0x7d, 0x70, 0x7c, 0xd5, 0xa6, 0x52, 0xe8,
	0xd1, 0x24, 0x97, 0x6b, 0xa6, 0x44, 0x90, 0xb3, 0x4e, 0x16, 0x67, 0x8e, 0x9d, 0xb1, 0xd6, 0x2f,
	0x8b, 0xf9, 0x23, 0xfa, 0xf4, 0x3b, 0x00, 0x00, 0xff, 0xff, 0xa0, 0x9c, 0xfa, 0x11, 0xe1, 0x03,
	0x00, 0x00,
}
