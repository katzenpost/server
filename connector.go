// connector.go - Katzenpost server connector.
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
	"sync"
	"time"

	"github.com/katzenpost/core/sphinx/constants"
	"github.com/op/go-logging"
)

type connector struct {
	sync.RWMutex
	sync.WaitGroup

	s     *Server
	log   *logging.Logger
	timer *time.Timer

	conns map[[constants.NodeIDLength]byte]*outgoingConn

	haltCh        chan interface{}
	forceUpdateCh chan interface{}

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

func (co *connector) halt() {
	close(co.haltCh)
	co.Wait()

	// Close all outgoing connections.
	close(co.closeAllCh)
	co.closeAllWg.Wait()
}

func (co *connector) forceUpdate() {
	// This deliberately uses a non-blocking write to a buffered channel so
	// that the resweeps happen reliably.  Since the resweep is comprehensive,
	// there's no benefit to queueing more than one resweep request, and the
	// periodic timer serves as a fallback.
	select {
	case co.forceUpdateCh <- true:
	default:
	}
}

func (co *connector) dispatchPacket(pkt *packet) {
	co.RLock()
	defer co.RUnlock()

	c, ok := co.conns[pkt.nextNodeHop.ID]
	if !ok {
		co.log.Debugf("Dropping packet: %v (No connection for destination)", pkt.id)
		pkt.dispose()
		return
	}

	c.dispatchPacket(pkt)
}

func (co *connector) worker() {
	const resweepInterval = 3 * time.Minute

	defer func() {
		co.Done()
	}()
	for {
		select {
		case <-co.haltCh:
			co.log.Debugf("Terminating gracefully.")
			return
		case <-co.forceUpdateCh:
			co.log.Debugf("Starting forced sweep.")
		case <-co.timer.C:
			co.log.Debugf("Starting periodic sweep.")
		}
		if !co.timer.Stop() {
			<-co.timer.C
		}

		// Start outgoing connections as needed, based on the PKI documents
		// and current time.
		co.spawnNewConns()

		co.log.Debugf("Done with sweep.")
		co.timer.Reset(resweepInterval)
	}

	// NOTREACHED
}

func (co *connector) spawnNewConns() {
	newPeerMap := co.s.pki.outgoingDestinations()

	// Traverse the connection table, to figure out which peers are actually
	// new.  Each outgoingConn object is responsible for determining when
	// the connection is stale.
	co.RLock()
	for id := range newPeerMap {
		if _, ok := co.conns[id]; ok {
			// There's a connection object for the peer already.
			delete(newPeerMap, id)
			continue
		}
	}
	co.RUnlock()

	// Spawn the new outgoingConn objects.
	for id, v := range newPeerMap {
		co.log.Debugf("Spawning connection to: '%v'.", nodeIDToPrintString(&id))
		c := newOutgoingConn(co, v)
		co.onNewConn(c)
	}
}

func (co *connector) onNewConn(c *outgoingConn) {
	var tmp [constants.NodeIDLength]byte
	copy(tmp[:], c.dst.LinkKey.Bytes())

	co.closeAllWg.Add(1)
	co.Lock()
	defer func() {
		co.Unlock()
		go c.worker()
	}()
	if _, ok := co.conns[tmp]; ok {
		// This should NEVER happen.  Not sure what the sensible thing to do is.
		co.log.Warningf("Connection to peer: '%v' already exists.", nodeIDToPrintString(&tmp))
	}
	co.conns[tmp] = c
}

func (co *connector) onClosedConn(c *outgoingConn) {
	var tmp [constants.NodeIDLength]byte
	copy(tmp[:], c.dst.LinkKey.Bytes())

	co.Lock()
	defer func() {
		co.Unlock()
		co.closeAllWg.Done()
	}()
	delete(co.conns, tmp)
}

func newConnector(s *Server) *connector {
	const initialSpawnDelay = 15 * time.Second

	co := new(connector)
	co.s = s
	co.log = s.newLogger("connector")
	co.timer = time.NewTimer(initialSpawnDelay)
	co.conns = make(map[[constants.NodeIDLength]byte]*outgoingConn)
	co.haltCh = make(chan interface{})
	co.forceUpdateCh = make(chan interface{}, 1) // See forceUpdate().
	co.closeAllCh = make(chan interface{})
	co.Add(1)

	go co.worker()
	return co
}
