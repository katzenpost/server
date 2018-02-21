// keyserver.go - Tether Kaetzchen.
// Copyright (C) 2018  David Stainton.
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
	"fmt"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/noise"
	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/userdb"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

const (
	tetherCapability = "tether"
	tetherVersion    = 0

	tetherStatusOk          = 0
	tetherStatusSyntaxError = 1
	tetherStatusNoIdentity  = 2
	tetherStatusNoSpool     = 3
	tetherStatusAuthError   = 4

	tetherAuthTokenLength = 80
)

type tetherRequest struct {
	Version   int
	User      string
	AuthToken string
	Command   string
	Sequence  int
}

type tetherResponse struct {
	Version    int
	StatusCode int
	QueueHint  int
	Sequence   int
	Payload    string
}

type kaetzchenTether struct {
	log  *logging.Logger
	glue glue.Glue

	params     Parameters
	jsonHandle codec.JsonHandle
}

func (k *kaetzchenTether) Capability() string {
	return tetherCapability
}

func (k *kaetzchenTether) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenTether) decryptToken(token []byte, sender *ecdh.PublicKey, recipient *ecdh.PrivateKey) ([]byte, error) {
	if len(token) != tetherAuthTokenLength {
		return nil, fmt.Errorf("block: invalid ciphertext length: %v (Expecting %v)", len(token), tetherAuthTokenLength)
	}

	// Decrypt the ciphertext into a plaintext.
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	recipientDH := noise.DHKey{
		Private: recipient.Bytes(),
		Public:  recipient.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeK,
		Initiator:     false,
		StaticKeypair: recipientDH,
		PeerStatic:    sender.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	plaintext, _, _, err := hs.ReadMessage(nil, token)
	if err != nil {
		return nil, err
	}

	return plaintext, err
}

func (k *kaetzchenTether) isAuthentic(authToken string, sender *ecdh.PublicKey, identityKey *ecdh.PrivateKey) bool {
	raw, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		k.log.Errorf("isAuthentic base64 decode failure: %s", err)
		return false
	}
	_, err = k.decryptToken(raw, sender, identityKey)
	if err != nil {
		k.log.Errorf("isAuthentic decrypt token failure: %s", err)
		return false
	}
	return true
}

func (k *kaetzchenTether) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}

	k.log.Debugf("Handling request: %v", id)
	resp := tetherResponse{
		Version:    tetherVersion,
		StatusCode: tetherStatusSyntaxError,
	}

	// Parse out the request payload.
	var req tetherRequest
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &k.jsonHandle)
	if err := dec.Decode(&req); err != nil {
		k.log.Debugf("Failed to decode request: %v (%v)", id, err)
		return k.encodeResp(&resp), nil
	}
	if req.Version != tetherVersion {
		k.log.Debugf("Failed to parse request: %v (invalid version: %v)", id, req.Version)
		return k.encodeResp(&resp), nil
	}

	// Query the public key.
	sender, err := k.glue.Provider().UserDB().Identity([]byte(req.User))
	switch err {
	case nil:
		resp.StatusCode = tetherStatusOk
		if k.glue.Provider().Spool() == nil {
			resp.StatusCode = tetherStatusNoSpool
			break
		}

		// Authenticate client.
		if !k.isAuthentic(req.AuthToken, sender, k.glue.Config().Debug.IdentityKey.ToECDH()) {
			k.log.Errorf("Tether client %s failed to authenticate", req.User)
			resp.StatusCode = tetherStatusAuthError
			break
		}

		// Retrieve a message.
		msg, _, remaining, err := k.glue.Provider().Spool().Get([]byte(req.User), true) // XXX fix me
		if err != nil {
			k.log.Errorf("KaetzenTether failure: %s", err)
		}
		resp.Payload = string(msg)
		resp.QueueHint = remaining
	case userdb.ErrNoSuchUser, userdb.ErrNoIdentity:
		// Treat the user being missing as the user not having an
		// identity key to make enumeration attacks minutely harder.
		resp.StatusCode = tetherStatusNoIdentity
	default:
	}
	if err != nil {
		k.log.Debugf("Failed to service request: %v (%v)", id, err)
	}

	return k.encodeResp(&resp), nil
}

func (k *kaetzchenTether) Halt() {
	// No termination required.
}

func (k *kaetzchenTether) encodeResp(resp *tetherResponse) []byte {
	var out []byte
	enc := codec.NewEncoderBytes(&out, &k.jsonHandle)
	enc.Encode(resp)
	return out
}

// NewTether constructs a new Tether Kaetzchen instance, providing the
// "tether" capability on the configured endpoint.
func NewTether(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenTether{
		log:    glue.LogBackend().GetLogger("kaetzchen/tether"),
		glue:   glue,
		params: make(Parameters),
	}
	k.jsonHandle.Canonical = true
	k.jsonHandle.ErrorIfNoField = true
	k.params[ParameterEndpoint] = cfg.Endpoint

	return k, nil
}
