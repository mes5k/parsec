// Code generated by protoc-gen-go. DO NOT EDIT.
// source: asym_verify.proto

package asym_verify

import (
	fmt "fmt"
	math "math"

	"github.com/docker/parsec/client/operations/key_attributes"
	proto "github.com/golang/protobuf/proto"
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

type OpAsymmetricVerifyProto struct {
	KeyName              string                     `protobuf:"bytes,1,opt,name=key_name,json=keyName,proto3" json:"key_name,omitempty"`
	KeyLifetime          key_attributes.KeyLifetime `protobuf:"varint,2,opt,name=key_lifetime,json=keyLifetime,proto3,enum=key_attributes.KeyLifetime" json:"key_lifetime,omitempty"`
	Hash                 []byte                     `protobuf:"bytes,3,opt,name=hash,proto3" json:"hash,omitempty"`
	Signature            []byte                     `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *OpAsymmetricVerifyProto) Reset()         { *m = OpAsymmetricVerifyProto{} }
func (m *OpAsymmetricVerifyProto) String() string { return proto.CompactTextString(m) }
func (*OpAsymmetricVerifyProto) ProtoMessage()    {}
func (*OpAsymmetricVerifyProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_f34b7b28662c533f, []int{0}
}

func (m *OpAsymmetricVerifyProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OpAsymmetricVerifyProto.Unmarshal(m, b)
}
func (m *OpAsymmetricVerifyProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OpAsymmetricVerifyProto.Marshal(b, m, deterministic)
}
func (m *OpAsymmetricVerifyProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OpAsymmetricVerifyProto.Merge(m, src)
}
func (m *OpAsymmetricVerifyProto) XXX_Size() int {
	return xxx_messageInfo_OpAsymmetricVerifyProto.Size(m)
}
func (m *OpAsymmetricVerifyProto) XXX_DiscardUnknown() {
	xxx_messageInfo_OpAsymmetricVerifyProto.DiscardUnknown(m)
}

var xxx_messageInfo_OpAsymmetricVerifyProto proto.InternalMessageInfo

func (m *OpAsymmetricVerifyProto) GetKeyName() string {
	if m != nil {
		return m.KeyName
	}
	return ""
}

func (m *OpAsymmetricVerifyProto) GetKeyLifetime() key_attributes.KeyLifetime {
	if m != nil {
		return m.KeyLifetime
	}
	return key_attributes.KeyLifetime_Volatile
}

func (m *OpAsymmetricVerifyProto) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *OpAsymmetricVerifyProto) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type ResultAsymmetricVerifyProto struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ResultAsymmetricVerifyProto) Reset()         { *m = ResultAsymmetricVerifyProto{} }
func (m *ResultAsymmetricVerifyProto) String() string { return proto.CompactTextString(m) }
func (*ResultAsymmetricVerifyProto) ProtoMessage()    {}
func (*ResultAsymmetricVerifyProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_f34b7b28662c533f, []int{1}
}

func (m *ResultAsymmetricVerifyProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResultAsymmetricVerifyProto.Unmarshal(m, b)
}
func (m *ResultAsymmetricVerifyProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResultAsymmetricVerifyProto.Marshal(b, m, deterministic)
}
func (m *ResultAsymmetricVerifyProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResultAsymmetricVerifyProto.Merge(m, src)
}
func (m *ResultAsymmetricVerifyProto) XXX_Size() int {
	return xxx_messageInfo_ResultAsymmetricVerifyProto.Size(m)
}
func (m *ResultAsymmetricVerifyProto) XXX_DiscardUnknown() {
	xxx_messageInfo_ResultAsymmetricVerifyProto.DiscardUnknown(m)
}

var xxx_messageInfo_ResultAsymmetricVerifyProto proto.InternalMessageInfo

func init() {
	proto.RegisterType((*OpAsymmetricVerifyProto)(nil), "asym_verify.OpAsymmetricVerifyProto")
	proto.RegisterType((*ResultAsymmetricVerifyProto)(nil), "asym_verify.ResultAsymmetricVerifyProto")
}

func init() { proto.RegisterFile("asym_verify.proto", fileDescriptor_f34b7b28662c533f) }

var fileDescriptor_f34b7b28662c533f = []byte{
	// 201 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x4c, 0x2c, 0xae, 0xcc,
	0x8d, 0x2f, 0x4b, 0x2d, 0xca, 0x4c, 0xab, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x46,
	0x12, 0x92, 0x12, 0xc9, 0x4e, 0xad, 0x8c, 0x4f, 0x2c, 0x29, 0x29, 0xca, 0x4c, 0x2a, 0x2d, 0x49,
	0x2d, 0x86, 0x28, 0x51, 0x5a, 0xc6, 0xc8, 0x25, 0xee, 0x5f, 0xe0, 0x58, 0x5c, 0x99, 0x9b, 0x9b,
	0x5a, 0x52, 0x94, 0x99, 0x1c, 0x06, 0x56, 0x1c, 0x00, 0xd6, 0x2e, 0xc9, 0xc5, 0x01, 0xd2, 0x93,
	0x97, 0x98, 0x9b, 0x2a, 0xc1, 0xa8, 0xc0, 0xa8, 0xc1, 0x19, 0xc4, 0x9e, 0x9d, 0x5a, 0xe9, 0x97,
	0x98, 0x9b, 0x2a, 0x64, 0xc7, 0xc5, 0x03, 0x92, 0xca, 0xc9, 0x4c, 0x4b, 0x2d, 0xc9, 0xcc, 0x4d,
	0x95, 0x60, 0x52, 0x60, 0xd4, 0xe0, 0x33, 0x92, 0xd6, 0x43, 0xb3, 0xc3, 0x3b, 0xb5, 0xd2, 0x07,
	0xaa, 0x24, 0x88, 0x3b, 0x1b, 0xc1, 0x11, 0x12, 0xe2, 0x62, 0xc9, 0x48, 0x2c, 0xce, 0x90, 0x60,
	0x56, 0x60, 0xd4, 0xe0, 0x09, 0x02, 0xb3, 0x85, 0x64, 0xb8, 0x38, 0x8b, 0x33, 0xd3, 0xf3, 0x12,
	0x4b, 0x4a, 0x8b, 0x52, 0x25, 0x58, 0xc0, 0x12, 0x08, 0x01, 0x25, 0x59, 0x2e, 0xe9, 0xa0, 0xd4,
	0xe2, 0xd2, 0x9c, 0x12, 0xac, 0x6e, 0x4d, 0x62, 0x03, 0x7b, 0xc7, 0x18, 0x10, 0x00, 0x00, 0xff,
	0xff, 0x64, 0xa9, 0x77, 0x79, 0x06, 0x01, 0x00, 0x00,
}
