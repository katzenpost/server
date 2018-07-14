// zcash.go - Zcash transaction submition Kaetzchen.
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
	"errors"
	"net/http"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/katzenpost/server/config"
	"github.com/katzenpost/server/internal/glue"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

const (
	currencyCapability = "currency"
	currencyVersion    = 0
	currencyTicker     = "ticker"
)

var errInvalidCurrencyRequest = errors.New("kaetzchen/currency: invalid request")

type currencyRequest struct {
	Version int
	Tx      string
	Ticker  string
}

type kaetzchenCurrency struct {
	log  *logging.Logger
	glue glue.Glue

	params     Parameters
	jsonHandle codec.JsonHandle

	id      uint64 // atomic, so must stay 64-bit aligned
	rpcUser string
	rpcPass string
	rpcUrl  string
}

func (k *kaetzchenCurrency) Capability() string {
	return currencyCapability
}

func (k *kaetzchenCurrency) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenCurrency) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if hasSURB {
		k.log.Debugf("Ignoring request: %v, erroneously contains a SURB.", id)
		return nil, ErrNoResponse
	}

	k.log.Debugf("Handling request: %v", id)

	// Parse out the request payload.
	var req currencyRequest
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &k.jsonHandle)
	if err := dec.Decode(&req); err != nil {
		k.log.Debugf("Failed to decode request: %v (%v)", id, err)
		return nil, errInvalidCurrencyRequest
	}

	// Sanity check the request.
	if req.Version != currencyVersion {
		k.log.Debugf("Failed to parse request: %v (invalid version: %v)", id, req.Version)
		return nil, errInvalidCurrencyRequest
	}
	if req.Ticker != k.params[currencyTicker] {
		k.log.Debugf("Failed to parse request: %v (currency ticker mismatch: %v)", id, req.Ticker)
		return nil, errInvalidCurrencyRequest
	}

	// Send request to HTTP RPC.
	err := k.sendTransaction(req.Tx)
	if err != nil {
		k.log.Debug("Failed to send currency transaction request: %v (%v)", id, err)
	}
	return nil, ErrNoResponse
}

func (k *kaetzchenCurrency) NextID() uint64 {
	return atomic.AddUint64(&k.id, 1)
}

func (k *kaetzchenCurrency) sendTransaction(txHex string) error {
	k.log.Debug("sendTransaction")

	// marshall new transaction blob
	allowHighFees := true
	cmd := btcjson.NewSendRawTransactionCmd(txHex, &allowHighFees)
	txId := k.NextID() // XXX todo: persist transaction ID to disk
	marshalledJSON, err := btcjson.MarshalCmd(txId, cmd)
	bodyReader := bytes.NewReader(marshalledJSON)

	// create an http request
	httpReq, err := http.NewRequest("POST", k.rpcUrl, bodyReader)
	if err != nil {
		return err
	}
	httpReq.Close = true
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(k.rpcUser, k.rpcPass)

	// send http request
	client := http.Client{}
	httpResponse, err := client.Do(httpReq)
	k.log.Debugf("currency RPC response status: %s", httpResponse.Status)

	return err
}

func (k *kaetzchenCurrency) Halt() {
	// No termination required.
}

// NewCurrency constructs a new Currency Kaetzchen instance, providing the
// "currency" capability on the configured endpoint.
// XXX todo: load last tx ID from disk
func NewCurrency(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	var rpcUser string
	var rpcPass string
	var rpcUrl string
	var ok bool
	rpcUser, ok = cfg.Config["rpcUser"].(string)
	if !ok {
		return nil, errors.New("failed to get Currency rpcUser from config file")
	}
	rpcPass, ok = cfg.Config["rpcPass"].(string)
	if !ok {
		return nil, errors.New("failed to get Currency rpcPass from config file")
	}
	rpcUrl, ok = cfg.Config["rpcUrl"].(string)
	if !ok {
		return nil, errors.New("failed to get Currency rpcUrl from config file")
	}
	if rpcUrl == "" {
		return nil, errors.New("failure, didn't find currency client rpc parameters in the config")
	}
	k := &kaetzchenCurrency{
		log:     glue.LogBackend().GetLogger("kaetzchen/currency"),
		glue:    glue,
		params:  make(Parameters),
		rpcUser: rpcUser,
		rpcPass: rpcPass,
		rpcUrl:  rpcUrl,
	}
	k.jsonHandle.Canonical = true
	k.jsonHandle.ErrorIfNoField = true
	k.params[ParameterEndpoint] = cfg.Endpoint
	if cfg.Config[currencyTicker] == "" {
		return nil, errors.New("failure, didn't find currency ticker parameter in the config")
	}
	k.params[currencyTicker] = cfg.Config[currencyTicker]
	k.log.Debug("<< new currency service created!")
	return k, nil
}
