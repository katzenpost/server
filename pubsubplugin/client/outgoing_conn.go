// outgoing_conn.go - out going client plugin connection
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

// Package pubsubplugin client is the client module a plugin system allowing mix network services
// to be added in any language. It implements a publish subscribe interface.
//
package client

import (
	"errors"
	"io"
	"net"

	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/pubsubplugin/common"
	"gopkg.in/op/go-logging.v1"
)

type outgoingConn struct {
	worker.Worker

	log *logging.Logger

	dialer *Dialer
	conn   net.Conn
}

func newOutgoingConn(dialer *Dialer, conn net.Conn, log *logging.Logger) *outgoingConn {
	return &outgoingConn{
		dialer: dialer,
		conn:   conn,
		log:    log,
	}
}

func (c *outgoingConn) readAppMessages() (*common.AppMessages, error) {
	lenPrefixBuf := make([]byte, 2)
	_, err := io.ReadFull(c.conn, lenPrefixBuf)
	if err != nil {
		return nil, err
	}
	lenPrefix := common.PrefixLengthDecode(lenPrefixBuf)
	responseBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(c.conn, responseBuf)
	if err != nil {
		return nil, err
	}
	egressCmd, err := common.EgressUnixSocketCommandFromBytes(responseBuf)
	if err != nil {
		return nil, err
	}
	if egressCmd.AppMessages == nil {
		return nil, errors.New("expected EgressUnixSocketCommand AppMessages to not be nil")
	}
	return egressCmd.AppMessages, nil
}

func (c *outgoingConn) unsubscribe(u *common.Unsubscribe) {
	serializedUnsubscribe, err := u.ToBytes()
	if err != nil {
		c.log.Errorf("unsubscribe error: %s", err)
	}
	serializedUnsubscribe = common.PrefixLengthEncode(serializedUnsubscribe)
	_, err = c.conn.Write(serializedUnsubscribe)
	if err != nil {
		c.log.Errorf("unsubscribe error: %s", err)
	}
}

func (c *outgoingConn) subscribe(subscribe *common.Subscribe) error {
	serializedSubscribe, err := subscribe.ToBytes()
	if err != nil {
		c.log.Errorf("subscribe error: %s", err)
	}
	serializedSubscribe = common.PrefixLengthEncode(serializedSubscribe)
	_, err = c.conn.Write(serializedSubscribe)
	if err != nil {
		c.log.Errorf("subscribe error: %s", err)
	}
	return err
}

func (c *outgoingConn) worker() {
	defer func() {
		// XXX TODO: stuff to shutdown
	}()
	for {
		newMessages, err := c.readAppMessages()
		if err != nil {
			c.log.Errorf("failure to read new messages from plugin: %s", err)
			return
		}
		select {
		case <-c.HaltCh():
			return
		case c.dialer.incomingCh <- newMessages:
		case rawCmd := <-c.dialer.outgoingCh:
			switch cmd := rawCmd.(type) {
			case *common.Unsubscribe:
				c.unsubscribe(cmd)
			case *common.Subscribe:
				c.subscribe(cmd)
			default:
				c.log.Errorf("outgoingConn received invalid command type %T from Dialer", rawCmd)
			}
		}
	}
}

func (c *outgoingConn) getParameters() (*common.Parameters, error) {
	ingressCmd := &common.IngressUnixSocketCommand{
		GetParameters: &common.GetParameters{},
	}
	rawGetParams, err := ingressCmd.ToBytes()
	if err != nil {
		return nil, err
	}
	rawGetParams = common.PrefixLengthEncode(rawGetParams)
	_, err = c.conn.Write(rawGetParams)
	if err != nil {
		return nil, err
	}

	// read response
	lenPrefixBuf := make([]byte, 2)
	_, err = io.ReadFull(c.conn, lenPrefixBuf)
	if err != nil {
		return nil, err
	}
	lenPrefix := common.PrefixLengthDecode(lenPrefixBuf)
	responseBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(c.conn, responseBuf)
	if err != nil {
		return nil, err
	}

	egressCmd, err := common.EgressUnixSocketCommandFromBytes(responseBuf)
	if err != nil {
		return nil, err
	}
	if egressCmd.Parameters == nil {
		return nil, errors.New("expected EgressUnixSocketCommand Parameters to not be nil")
	}
	return egressCmd.Parameters, nil
}
