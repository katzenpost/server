// incoming_conn.go - Katzenpost server incoming connection handler.
// Copyright (C) 2017  Yawning Angel.
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

package server

import (
	"container/list"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/op/go-logging"
)

var incomingConnID uint64

type incomingConn struct {
	s   *Server
	l   *listener
	c   net.Conn
	e   *list.Element
	w   *wire.Session
	log *logging.Logger

	id         uint64
	fromClient bool
	canSend    bool
}

func (c *incomingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// XXX/provider: Set c.fromClient iff the PeerCredentials belong to a
	// client.
	if c.s.cfg.Server.IsProvider {
		panic("BUG: Provider operation not implemented yet")
	}

	// Well, the peer has to be a mix since we're not a provider, or the user
	// is unknown.
	c.fromClient = false
	isValid := false
	c.canSend, isValid = c.s.pki.authenticateIncoming(creds)
	return isValid
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.c.Close()
		c.l.onClosedConn(c) // Remove from the connection list.
	}()

	// Allocate the session struct.
	cfg := &wire.SessionConfig{
		Authenticator:     c,
		AdditionalData:    []byte(c.s.cfg.Server.Identifier),
		AuthenticationKey: c.s.identity,
		RandomReader:      rand.Reader,
	}
	var err error
	c.w, err = wire.NewSession(cfg, false)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer c.w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.s.cfg.Debug.HandshakeTimeout) * time.Millisecond
	c.c.SetDeadline(time.Now().Add(timeoutMs))
	if err = c.w.Initialize(c.c); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}
	c.c.SetDeadline(time.Time{})

	// Ensure that there's only one incoming conn from any given peer, though
	// this only really matters for user sessions.  The easiest thing to do
	// is "oldest connection wins" since that doesn't require one connection
	// closing another.
	//
	// TODO: Newest connection wins is more annoying to implement, but better
	// behavior.
	for _, s := range c.s.listeners {
		if !s.isConnUnique(c) {
			c.log.Errorf("Connection with credentials already exists.")
			return
		}
	}

	// Start the reauthenticate ticker.
	reauth := time.NewTicker(15 * time.Second)
	defer reauth.Stop()

	// Start reading from the peer.
	commandCh := make(chan commands.Command)
	commandCloseCh := make(chan interface{})
	defer close(commandCloseCh)
	go func() {
		defer close(commandCh)
		for {
			rawCmd, err := c.w.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			select {
			case commandCh <- rawCmd:
			case <-commandCloseCh:
				// c.worker() is returning for some reason, give up on
				// trying to write the command, and just return.
				return
			}
		}
	}()

	// Process incoming packets.
	for {
		var rawCmd commands.Command
		ok := false

		select {
		case <-c.l.closeAllCh:
			// Server is getting shutdown, all connections are being closed.
			return
		case <-reauth.C:
			// Each incoming conn has a periodic 1/15 Hz timer to wake up
			// and re-authenticate the connection to handle the PKI document(s)
			// and or the user database changing.
			//
			// Doing it this way avoids a good amount of complexity at the
			// the cost of extra authenticates (which should be fairly fast).
			if !c.IsPeerValid(c.w.PeerCredentials()) {
				c.log.Debugf("Disconnecting, peer reauthenticate failed.")
				return
			}
			continue
		case rawCmd, ok = <-commandCh:
			if !ok {
				return
			}
		}

		// TODO: It's possible that a peer connects right at the tail end
		// before we start allowing "early" packets, resulting in c.canSend
		// being false till the reauth timer fires.  This probably isn't a
		// big deal since everyone should be using NTP anyway.
		if !c.canSend {
			// The peer's PKI document entry isn't for the current epoch,
			// or within the slack time.
			c.log.Debugf("Dropping mix command received out of epoch.")
			continue
		}

		if !c.s.cfg.Server.IsProvider || !c.fromClient {
			ok = c.onMixCommand(rawCmd)
		} else {
			// XXX/provider: This is a connection from a client.  It *could*
			// just be a SendPacket, but it may also be attempting to retreive
			// from the mail spool.
			panic("BUG: Provider operation not implemented yet")
		}
		if !ok {
			// Catastrophic failure in command processing, or a disconnect.
			return
		}
	}

	// NOTREACHED
}

func (c *incomingConn) onMixCommand(rawCmd commands.Command) bool {
	switch cmd := rawCmd.(type) {
	case *commands.SendPacket:
		err := c.onSendPacket(cmd)
		if err == nil {
			return true
		}
		c.log.Debugf("Failed to handle SendPacket: %v", err)
	case *commands.Disconnect:
		c.log.Debugf("Received disconnect from peer.")
	default:
		c.log.Debugf("Received unexpected mix command: %t", cmd)
	}
	return false
}

func (c *incomingConn) onSendPacket(cmd *commands.SendPacket) error {
	pkt := newPacket()
	if err := pkt.copyToRaw(cmd.SphinxPacket); err != nil {
		return err
	}

	c.log.Debugf("Handing off packet: %v", pkt.id)

	// For purposes of fudging the scheduling delay based on queue dwell
	// time, we treat the moment the packet is inserted into the crypto
	// worker queue as the time the packet was received.
	pkt.recvAt = monotime.Now()
	c.s.inboundPackets.In() <- pkt

	return nil
}

func newIncomingConn(l *listener, conn net.Conn) *incomingConn {
	c := new(incomingConn)
	c.s = l.s
	c.l = l
	c.c = conn
	c.id = atomic.AddUint64(&incomingConnID, 1) // Diagnostic only, wrapping is fine.
	c.log = l.s.newLogger(fmt.Sprintf("incoming:%d", c.id))

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
