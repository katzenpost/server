// keyserver_test.go - Tests for the Kaetzchen keyserver.
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

func TestKeyserver(t *testing.T) {
	require := require.New(t)

	cfg := &config.Kaetzchen{
		Capability: "keyserver",
		Endpoint:   "endpoint",
		Config:     map[string]interface{}{},
		Disable:    false,
	}

	idKey, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	userKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err)

	linkKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err)

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
	keyserver, err := NewKeyserver(cfg, goo)
	require.NoError(err)

	jsonHandle := codec.JsonHandle{}
	jsonHandle.Canonical = true
	jsonHandle.ErrorIfNoField = true

	req := keyserverRequest{
		Version: keyserverVersion,
		User:    "alice",
	}

	var rawRequest []byte

	enc := codec.NewEncoderBytes(&rawRequest, &jsonHandle)
	err = enc.Encode(req)
	require.NoError(err)

	id := uint64(0)
	response, err := keyserver.OnRequest(id, rawRequest, true)
	require.NoError(err)

	var resp keyserverResponse
	dec := codec.NewDecoderBytes(bytes.TrimRight(response, "\x00"), &jsonHandle)
	err = dec.Decode(&resp)
	require.NoError(err)

	require.Equal(keyserverVersion, resp.Version)
	require.Equal(keyserverStatusOk, resp.StatusCode)
	require.Equal(req.User, resp.User)

	pubKeyBytes, err := hex.DecodeString(resp.PublicKey)
	require.NoError(err)
	pubKey := new(ecdh.PublicKey)
	err = pubKey.FromBytes(pubKeyBytes)
	require.NoError(err)
	require.True(userKey.PublicKey().Equal(pubKey))
}
