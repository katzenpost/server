// panda.go - PANDA Kaetzchen.
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
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

// PANDA - Phrase Automated Nym Discovery Authentication
//
// This Kaetzchen service was inspired by AGL's appengine Panda server:
//
// https://github.com/agl/pond/blob/master/panda/appengine-server/panda/main.go

const (
	pandaCapability = "panda"
	pandaVersion    = 0

	pandaStatusReceived1            = 0
	pandaStatusReceived2            = 1
	pandaStatusSyntaxError          = 2
	pandaStatusTagContendedError    = 3
	pandaStatusRequestRecordedError = 4
	pandaStatusStorageError         = 5

	PandaTagLength = 32
)

var ErrNoSuchPandaTag = errors.New("Error: no such PANDA tag")

type pandaRequest struct {
	Version int
	Tag     string
	Message string
}

type pandaResponse struct {
	Version    int
	StatusCode int
	Message    string
}

// PandaPosting
type PandaPosting struct {
	UnixTime int64
	A, B     []byte
}

// Expired returns true if the posting is
// older than the specified expiration duration.
func (p *PandaPosting) Expired(expiration time.Duration) bool {
	postingTime := time.Unix(p.UnixTime, 0)
	return postingTime.After(postingTime.Add(expiration))
}

func postingFromRequest(req *pandaRequest) (*[PandaTagLength]byte, *PandaPosting, error) {
	tagRaw, err := hex.DecodeString(req.Tag)
	if err != nil {
		return nil, nil, err
	}
	if len(tagRaw) != PandaTagLength {
		return nil, nil, errors.New("postingFromRequest failure: tag not 32 bytes in length")
	}
	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		return nil, nil, err
	}
	p := &PandaPosting{
		UnixTime: time.Now().Unix(),
		A:        message,
		B:        nil,
	}
	tag := [PandaTagLength]byte{}
	copy(tag[:], tagRaw)
	return &tag, p, nil
}

// PandaPostStorage is the interface provided by all PANDA server
// storage implementations.
type PandaPostStorage interface {

	// Put stores a posting in the data store
	// such that it is referenced by the given tag.
	Put(tag *[PandaTagLength]byte, posting *PandaPosting) error

	// Get returns a posting from the data store
	// that is referenced by the given tag.
	Get(tag *[PandaTagLength]byte) (*PandaPosting, error)

	// Replace replaces the stored posting.
	Replace(tag *[PandaTagLength]byte, posting *PandaPosting) error

	// Vacuum removes the postings that have expired.
	Vacuum(expiration time.Duration) error
}

type kaetzchenPanda struct {
	sync.Mutex

	log  *logging.Logger
	glue glue.Glue

	params     Parameters
	jsonHandle codec.JsonHandle
	store      PandaPostStorage
	expiration time.Duration
}

// Capability returns our "service description string"
// (nothing to do with object capability)
func (k *kaetzchenPanda) Capability() string {
	return pandaCapability
}

// Parameters returns the Panda service parameters,
// containing the Panda posting storage expiration duration string.
func (k *kaetzchenPanda) Parameters() Parameters {
	return k.params
}

// OnRequest services a client request and returns the reply.
func (k *kaetzchenPanda) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}
	k.log.Debugf("Handling request: %v", id)
	resp := pandaResponse{
		Version:    pandaVersion,
		StatusCode: pandaStatusSyntaxError,
	}

	// Parse out the request payload.
	var req pandaRequest
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &k.jsonHandle)
	if err := dec.Decode(&req); err != nil {
		k.log.Debugf("failed to decode request: %v (%v)", id, err)
		return k.encodeResp(&resp), nil
	}
	if req.Version != pandaVersion {
		k.log.Debugf("failed to parse request: %v (invalid version: %v)", id, req.Version)
		return k.encodeResp(&resp), nil
	}
	if len(req.Message) == 0 {
		k.log.Debugf("failure: message size is zero")
		return k.encodeResp(&resp), nil
	}
	tag, newPosting, err := postingFromRequest(&req)
	if err != nil {
		k.log.Debugf("failure: cannot decode tag and message")
		return k.encodeResp(&resp), nil
	}

	k.Lock()
	defer k.Unlock()

	storedPosting, err := k.store.Get(tag)
	if err == ErrNoSuchPandaTag || err == nil && storedPosting.Expired(k.expiration) {
		k.store.Put(tag, newPosting)
		resp.StatusCode = pandaStatusReceived1
		return k.encodeResp(&resp), nil
	}
	if err != nil {
		resp.StatusCode = pandaStatusStorageError
		return k.encodeResp(&resp), nil
	}
	if len(storedPosting.B) > 0 {
		if bytes.Equal(storedPosting.A, newPosting.A) {
			resp.Message = base64.StdEncoding.EncodeToString(storedPosting.B)
			resp.StatusCode = pandaStatusReceived2
			return k.encodeResp(&resp), nil
		} else if bytes.Equal(storedPosting.B, newPosting.A) {
			resp.Message = base64.StdEncoding.EncodeToString(storedPosting.A)
			resp.StatusCode = pandaStatusReceived2
			return k.encodeResp(&resp), nil
		} else {
			resp.StatusCode = pandaStatusTagContendedError
			return k.encodeResp(&resp), nil
		}
		// not reached
	}
	if bytes.Equal(storedPosting.A, newPosting.A) {
		resp.StatusCode = pandaStatusRequestRecordedError
		return k.encodeResp(&resp), nil
	}
	storedPosting.B = newPosting.A
	err = k.store.Replace(tag, storedPosting)
	if err != nil {
		resp.StatusCode = pandaStatusStorageError
		return k.encodeResp(&resp), nil
	}

	resp.Message = base64.StdEncoding.EncodeToString(storedPosting.A)
	resp.StatusCode = pandaStatusReceived2
	return k.encodeResp(&resp), nil
}

// Halt halts this service.
func (k *kaetzchenPanda) Halt() {
	// No termination required.
}

func (k *kaetzchenPanda) encodeResp(resp *pandaResponse) []byte {
	var out []byte
	enc := codec.NewEncoderBytes(&out, &k.jsonHandle)
	enc.Encode(resp)
	return out
}

// NewPanda constructs a new Panda Kaetzchen instance, providing the
// "panda" service on the configured endpoint.
func NewPanda(cfg *config.Kaetzchen, glue glue.Glue, store PandaPostStorage) (Kaetzchen, error) {
	k := &kaetzchenPanda{
		log:    glue.LogBackend().GetLogger("kaetzchen/panda"),
		glue:   glue,
		params: make(Parameters),
		store:  store,
	}
	k.jsonHandle.Canonical = true
	k.jsonHandle.ErrorIfNoField = true
	e, ok := cfg.Config["expiration"]
	if !ok {
		return nil, errors.New("Panda Kaetzchen failure: configuration MUST specify an expiration duration")
	}
	expiration, ok := e.(string)
	if !ok {
		return nil, errors.New("Panda Kaetzchen failure: expiration duration must be a string")
	}
	duration, err := time.ParseDuration(expiration)
	if err != nil {
		return nil, errors.New("Panda Kaetzchen failure: invalid duration string")
	}
	k.expiration = duration
	k.params["expiration"] = expiration
	k.params[ParameterEndpoint] = cfg.Endpoint

	return k, nil
}
