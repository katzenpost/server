// scheduler.go - Katzenpost server scheduler.
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
	"math"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/queue"
	"github.com/op/go-logging"
)

type serverScheduler struct {
	sync.WaitGroup

	s     *Server
	timer *time.Timer
	ch    *channels.InfiniteChannel
	queue *queue.PriorityQueue
	log   *logging.Logger

	haltCh chan interface{}
}

func (sch *serverScheduler) halt() {
	close(sch.haltCh)
	sch.Wait()
	sch.ch.Close()
}

func (sch *serverScheduler) worker() {
	ch := sch.ch.Out()
	timerSlack := time.Duration(sch.s.cfg.Debug.SchedulerSlack) * time.Millisecond
	defer func() {
		sch.timer.Stop()
		sch.Done()
	}()
	for {
		// The vast majority of the time the scheduler will be idle waiting on
		// new packets or for a packet in the priority queue to be eligible
		// for dispatch.  This is where the actual "mix" part of the mix
		// network happens.
		//
		// There's only a single go routine responsible for packet scheduling
		// under the assumption that this isn't CPU intensive in the slightest,
		// and that the main performance gains come from parallelizing the
		// crypto, and being clever about congestion management.
		select {
		case <-sch.haltCh:
			// Th-th-th-that's all folks.
			sch.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			// New packet from the crypto workers.
			//
			// Note: This assumes that pkt.delay has already been adjusted to
			// account for the packet processing time up to the point where
			// the packet was enqueued.
			pkt := e.(*packet)

			// Ensure the peer is valid, by querying the PKI, and NOT the
			// outgoing connection table.
			if sch.s.pki.isValidForwardDest(&pkt.nextNodeHop.ID) {
				sch.log.Debugf("Enqueueing packet: %v delta-t: %v", pkt.id, pkt.delay)
				sch.queue.Enqueue(uint64(monotime.Now()+pkt.delay), pkt)
			} else {
				sID := nodeIDToPrintString(&pkt.nextNodeHop.ID)
				sch.log.Debugf("Dropping packet: %v Next hop is invalid: %v", pkt.id, sID)
				pkt.dispose()
			}
		case <-sch.timer.C:
			// Packet delay probably passed, packet dispatch handled as
			// part of rescheduling the timer.
		}

		// Dispatch packets if possible and reschedule the next wakeup.
		if !sch.timer.Stop() {
			<-sch.timer.C
		}
		for {
			// Peek at the next packet in the queue.
			e := sch.queue.Peek()
			if e == nil {
				// The queue is empty, just reschedule for the max duration,
				// when there are packets to schedule, we'll get woken up.
				sch.timer.Reset(math.MaxInt64)
				break
			}

			// Figure out if the packet needs to be handled now.
			now := monotime.Now()
			dispatchAt := time.Duration(e.Priority)
			if dispatchAt > now {
				// Packet dispatch will happen at a later time, so schedule
				// the next timer tick, and go back to waiting for something
				// interesting to happen.
				sch.timer.Reset(dispatchAt - now)
				break
			}

			// The packet will be dispatched somehow, so remove it from the
			// queue, and do the type assertion.
			sch.queue.Pop()
			pkt := (e.Value).(*packet)

			// Packet dispatch time is now or in the past, so it needs to be
			// forwarded to the appropriate hop.
			if now-dispatchAt > timerSlack {
				// ... unless the deadline has been blown by more than the
				// configured slack time.
				sch.log.Debugf("Dropping packet: %v (Deadline blown by %v)", pkt.id, now-dispatchAt)
				pkt.dispose()
			} else {
				// Dispatch the packet to the next hop.  Note that the callee
				// may still drop the packet, for example if there isn't a
				// link establised to the peer, or if the link is overloaded.
				//
				// Note: Callee takes ownership.
				pkt.dispatchAt = now
				sch.s.connector.dispatchPacket(pkt)
			}
		}
	}

	// NOTREACHED
}

func newScheduler(s *Server) *serverScheduler {
	sch := new(serverScheduler)
	sch.s = s
	sch.queue = queue.New()
	sch.log = s.newLogger("scheduler")
	sch.ch = channels.NewInfiniteChannel()
	sch.timer = time.NewTimer(math.MaxInt64)
	sch.haltCh = make(chan interface{})
	sch.Add(1)

	go sch.worker()
	return sch
}
