// panda_test.go - Tests for Panda Kaetzchen.
// Copyright (C) 2018  David Stainton
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

package kaetzchen

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/server/config"
	"github.com/stretchr/testify/require"
	"github.com/ugorji/go/codec"
)

func TestPanda(t *testing.T) {
	require := require.New(t)

	cfg := &config.Kaetzchen{
		Capability: "panda",
		Endpoint:   "endpoint",
		Config: map[string]interface{}{
			"expiration": "3h",
		},
		Disable: false,
	}

	idKey, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err, "wtf")

	userKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")

	linkKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")

	mockProvider := &mockProvider{
		userName: "alice",
		userKey:  userKey.PublicKey(),
	}
	goo := &mockGlue{
		s: &mockServer{
			logBackend: logBackend,
			provider:   mockProvider,
			linkKey:    linkKey,
			cfg: &config.Config{
				Server:     &config.Server{},
				Logging:    &config.Logging{},
				Provider:   &config.Provider{},
				PKI:        &config.PKI{},
				Management: &config.Management{},
				Debug: &config.Debug{
					IdentityKey: idKey,
				},
			},
		},
	}
	store := NewInMemoryPandaStorage()
	panda, err := NewPanda(cfg, goo, store)
	require.NoError(err, "wtf")

	tag := [32]byte{}
	_, err = rand.Reader.Read(tag[:])
	require.NoError(err, "wtf")

	// phase 1

	req := pandaRequest{
		Version: pandaVersion,
		Tag:     hex.EncodeToString(tag[:]),
		Message: base64.StdEncoding.EncodeToString([]byte("message1")),
	}
	var request []byte
	jsonHandle := codec.JsonHandle{}
	jsonHandle.Canonical = true
	jsonHandle.ErrorIfNoField = true

	enc := codec.NewEncoderBytes(&request, &jsonHandle)
	err = enc.Encode(req)
	require.NoError(err, "wtf")

	serviceID := uint64(0)
	response, err := panda.OnRequest(serviceID, request, true)
	require.NoError(err, "wtf")

	var resp pandaResponse
	dec := codec.NewDecoderBytes(bytes.TrimRight(response, "\x00"), &jsonHandle)
	err = dec.Decode(&resp)
	require.NoError(err, "wtf")

	require.Equal(pandaVersion, resp.Version)
	require.Equal(pandaStatusReceived1, resp.StatusCode)
	require.Equal(0, len(resp.Message))

	// phase 2

	req = pandaRequest{
		Version: pandaVersion,
		Tag:     hex.EncodeToString(tag[:]),
		Message: base64.StdEncoding.EncodeToString([]byte("message2")),
	}

	enc = codec.NewEncoderBytes(&request, &jsonHandle)
	err = enc.Encode(req)
	require.NoError(err, "wtf")

	response, err = panda.OnRequest(serviceID, request, true)
	require.NoError(err, "wtf")

	resp = pandaResponse{}
	dec = codec.NewDecoderBytes(bytes.TrimRight(response, "\x00"), &jsonHandle)
	err = dec.Decode(&resp)
	require.NoError(err, "wtf")

	require.Equal(pandaVersion, resp.Version)
	require.Equal(pandaStatusReceived2, resp.StatusCode)

	decodedMessage, err := base64.StdEncoding.DecodeString(resp.Message)
	require.NoError(err, "wtf")
	require.Equal("message1", string(decodedMessage))

	// phase 3

	req = pandaRequest{
		Version: pandaVersion,
		Tag:     hex.EncodeToString(tag[:]),
		Message: base64.StdEncoding.EncodeToString([]byte("message1")),
	}

	enc = codec.NewEncoderBytes(&request, &jsonHandle)
	err = enc.Encode(req)
	require.NoError(err, "wtf")

	response, err = panda.OnRequest(serviceID, request, true)
	require.NoError(err, "wtf")

	resp = pandaResponse{}
	dec = codec.NewDecoderBytes(bytes.TrimRight(response, "\x00"), &jsonHandle)
	err = dec.Decode(&resp)
	require.NoError(err, "wtf")

	require.Equal(pandaVersion, resp.Version)
	require.Equal(pandaStatusReceived2, resp.StatusCode)

	decodedMessage, err = base64.StdEncoding.DecodeString(resp.Message)
	require.NoError(err, "wtf")
	require.Equal("message2", string(decodedMessage))
}
