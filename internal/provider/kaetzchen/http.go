// http.go - Http Kaetzchen.
// Copyright (C) 2018  Yawning Angel.
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
	"errors"
	"io"
	"net/http"

	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"github.com/ugorji/go/codec"
	"github.com/yawning/bulb"
	"golang.org/x/net/proxy"
	"gopkg.in/op/go-logging.v1"
)

const httpCapability = "http"

type kaetzchenHttp struct {
	log *logging.Logger

	dialer     proxy.Dialer
	params     Parameters
	jsonHandle codec.JsonHandle
}

func (k *kaetzchenHttp) encodeResp(resp *http.Response) []byte {
	maxPayloadSize := 2048 // ass
	response := make([]byte, maxPayloadSize)
	if n, err := resp.Body.Read(response); err != nil {
		if err != io.EOF || n == 0 {
			return nil
		}
	}
	var out []byte
	enc := codec.NewEncoderBytes(&out, &k.jsonHandle)
	enc.Encode(resp)
	return out
}

func (k *kaetzchenHttp) Capability() string {
	return httpCapability
}

func (k *kaetzchenHttp) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenHttp) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}
	var req http.Request
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &k.jsonHandle)
	dec.Decode(&req)

	if err := dec.Decode(&req); err != nil {
		k.log.Debugf("Failed to decode request: %v (%v)", id, err)
		return nil, err
	}
	orkHTTPClient := &http.Client{Transport: &http.Transport{Dial: k.dialer.Dial}}
	resp, err := orkHTTPClient.Get(req.URL.String())
	if err != nil {
		k.log.Debug("kaetzchenHttp: http.Client.Get returned error")
		return nil, err
	}
	defer resp.Body.Close()
	r := k.encodeResp(resp)
	if r != nil {
		return r, nil
	}
	return nil, ErrNoResponse
}

func (k *kaetzchenHttp) Halt() {
}

func (k *kaetzchenHttp) getTorDialer(socketPath string) (proxy.Dialer, error) {
	// alternately, just use SOCKS5 directly and specify the port.
	if k.dialer != nil {
		return k.dialer, nil
	}
	c, err := bulb.Dial("unix", socketPath)
	if err != nil {
		k.log.Fatalf("failed to connect to control port: %v", err)
	}
	defer c.Close()
	if err := c.Authenticate(""); err != nil {
		k.log.Fatalf("Authentication failed: %v", err)
		return nil, err
	}
	dialer, err := c.Dialer(nil)
	if err != nil {
		return nil, err
	}
	k.dialer = dialer
	return dialer, err
}

func NewHttp(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenHttp{
		log:    glue.LogBackend().GetLogger("kaetzchen/http"),
		params: make(Parameters),
	}
	k.params[ParameterEndpoint] = cfg.Endpoint
	socket, ok := cfg.Config["TorControlSocketPath"]
	if !ok {
		return nil, errors.New("Panda Kaetzchen failure: configuration MUST specify socks socket path")
	}
	socketPath, ok := socket.(string)
	if !ok {
		return nil, errors.New("Panda Kaetzchen failure: expiration duration must be a string")
	}

	_, err := k.getTorDialer(socketPath)
	return k, err

}
