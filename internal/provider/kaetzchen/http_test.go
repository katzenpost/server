// http_test.go - Tests for HTTP Kaetzchen.
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
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/server/config"
	"github.com/stretchr/testify/require"
)

func TestHTTP(t *testing.T) {
	require := require.New(t)

	cfg := &config.Kaetzchen{
		Capability: "http",
		Endpoint:   "endpoint",
		Config: map[string]interface{}{
			"TorControlSocketPath": interface{}("blahsocketpath"),
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

	//socketDir, err := ioutil.TempDir("", "socksDir")
	//require.NoError(err, "wtf")

	goo := &mockGlue{
		s: &mockServer{
			logBackend: logBackend,
			provider:   mockProvider,
			linkKey:    linkKey,
			cfg: &config.Config{
				Server:  &config.Server{},
				Logging: &config.Logging{},
				Provider: &config.Provider{
					Kaetzchen: []*config.Kaetzchen{
						cfg,
					},
				},
				PKI:        &config.PKI{},
				Management: &config.Management{},
				Debug: &config.Debug{
					IdentityKey: idKey,
				},
			},
		},
	}

	_, err = NewHttp(cfg, goo)
	require.NoError(err, "wtf")

}
