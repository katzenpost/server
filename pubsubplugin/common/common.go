// common.go - common types shared between the pubsub client and server.
// Copyright (C) 2020  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package common include the common types used in the publish subscribe
// client and server modules.
//
package common

import (
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/core/crypto/rand"
)

const (
	// SubscriptionIDLength is the length of the Subscription ID.
	SubscriptionIDLength = 8

	// SpoolIDLength is the length of the spool identity.
	SpoolIDLength = 8
)

// PrefixLengthEncode encodes the given byte slice with
// two byte big endian length prefix encoding.
func PrefixLengthEncode(b []byte) []byte {
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(b)))
	b = append(lenPrefix, b...)
	return b
}

// PrefixLengthDecode decodes the first two bytes of the
// given byte slice as a uint16, big endian encoded.
func PrefixLengthDecode(b []byte) uint16 {
	return binary.BigEndian.Uint16(b[:2])
}

// Unsubscribe is used by the mix server to communicate an unsubscribe to
// the plugin.
type Unsubscribe struct {
	// SubscriptionID is the server generated subscription identity.
	SubscriptionID [SubscriptionIDLength]byte
}

// ToBytes returns a CBOR serialized Unsubscribe.
func (u *Unsubscribe) ToBytes() ([]byte, error) {
	serializedunsubscribe, err := cbor.Marshal(u)
	if err != nil {
		return nil, err
	}
	return serializedunsubscribe, nil
}

// Subscribe is the struct type used to establish a subscription with
// the plugin.
type Subscribe struct {
	// PacketID is the packet identity.
	PacketID uint64

	// SURBCount is the number of SURBs available to this subscription.
	SURBCount uint8

	// SubscriptionID is the server generated subscription identity.
	SubscriptionID [SubscriptionIDLength]byte

	// SpoolID is the spool identity.
	SpoolID [SpoolIDLength]byte

	// LastSpoolIndex is the last spool index which was received by the client.
	LastSpoolIndex uint64
}

// SubscribeToBytes encodes the given Subscribe as a CBOR byte blob.
func (s *Subscribe) ToBytes() ([]byte, error) {
	serializedSubscribe, err := cbor.Marshal(s)
	if err != nil {
		return nil, err
	}
	return serializedSubscribe, nil
}

// SubscribeFromBytes returns a Subscribe given a CBOR serialized Subscribe.
func SubscribeFromBytes(b []byte) (*Subscribe, error) {
	subscribe := Subscribe{}
	err := cbor.Unmarshal(b, &subscribe)
	if err != nil {
		return nil, err
	}
	return &subscribe, nil
}

// GenerateSubscriptionID returns a random subscription ID.
func GenerateSubscriptionID() [SubscriptionIDLength]byte {
	id := [SubscriptionIDLength]byte{}
	rand.Reader.Read(id[:])
	return id
}

// ClientSubscribe is used by the mixnet client to send a subscription
// request to the publish-subscribe application plugin.
type ClientSubscribe struct {
	// SpoolID is the spool identity.
	SpoolID [SpoolIDLength]byte

	// LastSpoolIndex is the last spool index which was received by the client.
	LastSpoolIndex uint64

	// Payload is the application specific payload which the client sends to
	// the plugin.
	Payload []byte
}

// ClientSubscribeFromBytes decodes a ClientSubscribe from the
// given CBOR byte blob.
func ClientSubscribeFromBytes(b []byte) (*ClientSubscribe, error) {
	clientSubscribe := ClientSubscribe{}
	err := cbor.Unmarshal(b, &clientSubscribe)
	if err != nil {
		return nil, err
	}
	return &clientSubscribe, nil
}

// AppMessages is the struct type used by the application plugin to
// send new messages to the server and eventually the subscribing client.
type AppMessages struct {
	// SubscriptionID is the server generated subscription identity.
	SubscriptionID [SubscriptionIDLength]byte

	// Messages should contain one or more spool messages.
	Messages []SpoolMessage
}

// ToBytes serializes AppMessages into a CBOR byte blob
// or returns an error.
func (m *AppMessages) ToBytes() ([]byte, error) {
	serialized, err := cbor.Marshal(m)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// MessagesToBytes returns a CBOR byte blob given a slice of type SpoolMessage.
func MessagesToBytes(messages []SpoolMessage) ([]byte, error) {
	serialized, err := cbor.Marshal(messages)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// AppMessagesFromBytes decodes the given CBOR byte blob
// into a AppMessages or returns an error.
func AppMessagesFromBytes(b []byte) (*AppMessages, error) {
	newMessages := AppMessages{}
	err := cbor.Unmarshal(b, &newMessages)
	if err != nil {
		return nil, err
	}
	return &newMessages, nil
}

// SpoolMessage is a spool message from the application plugin.
type SpoolMessage struct {
	// Index is the index value from whence the message came from.
	Index uint64

	// Payload contains the actual spool message contents which are
	// application specific.
	Payload []byte
}

// Parameters is an optional mapping that plugins can publish, these get
// advertised to clients in the MixDescriptor.
// The output of GetParameters() ends up being published in a map
// associating with the service names to service parameters map.
// This information is part of the Mix Descriptor which is defined here:
// https://github.com/katzenpost/core/blob/master/pki/pki.go
type Parameters map[string]string

// ParametersFromBytes returns Parameters given a CBOR byte blob.
// Otherwise an error is returned.
func ParametersFromBytes(b []byte) (*Parameters, error) {
	params := make(Parameters)
	err := cbor.Unmarshal(b, &params)
	if err != nil {
		return nil, err
	}
	return &params, nil
}

// ParametersToBytes returns a CBOR byte blob given a *Parameters.
func ParametersToBytes(params *Parameters) ([]byte, error) {
	rawParams, err := cbor.Marshal(params)
	if err != nil {
		return nil, err
	}
	return rawParams, nil
}

// GetParameters is used for querying the plugin over the unix socket
// to get the dynamic parameters after the plugin is started.
type GetParameters struct{}

// GetParametersFromBytes returns a *GetParameters given a CBOR byte blob
// or an error.
func GetParametersFromBytes(b []byte) (*GetParameters, error) {
	getParams := GetParameters{}
	err := cbor.Unmarshal(b, &getParams)
	if err != nil {
		return nil, err
	}
	return &getParams, nil
}

// GetParametersToBytes returns the CBOR representation of GetParameters.
func GetParametersToBytes() ([]byte, error) {
	rawGetParams, err := cbor.Marshal(&GetParameters{})
	if err != nil {
		return nil, err
	}
	return rawGetParams, nil
}
