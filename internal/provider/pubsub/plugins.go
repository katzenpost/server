// plugins.go - publish subscribe plugin system for mix network services
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

// Package pubsub implements support for provider side SURB based publish subscribe agents.
package pubsub

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/core/monotime"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/internal/constants"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/packet"
	"github.com/katzenpost/server/pubsubplugin"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/text/secure/precis"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

var (
	packetsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: constants.Namespace,
			Name:      "dropped_packets_total",
			Subsystem: constants.PubsubPluginSubsystem,
			Help:      "Number of dropped packets",
		},
	)
	pubsubRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: constants.Namespace,
			Name:      "requests_total",
			Subsystem: constants.PubsubPluginSubsystem,
			Help:      "Number of Pubsub requests",
		},
	)
	pubsubRequestsDuration = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Namespace: constants.Namespace,
			Name:      "requests_duration_seconds",
			Subsystem: constants.PubsubPluginSubsystem,
			Help:      "Duration of a pubsub request in seconds",
		},
	)
	pubsubRequestsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: constants.Namespace,
			Name:      "dropped_requests_total",
			Subsystem: constants.PubsubPluginSubsystem,
			Help:      "Number of total dropped pubsub requests",
		},
	)
	pubsubRequestsFailed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: constants.Namespace,
			Name:      "failed_requests_total",
			Subsystem: constants.PubsubPluginSubsystem,
			Help:      "Number of total failed pubsub requests",
		},
	)
	pubsubRequestsTimer *prometheus.Timer
)

func init() {
	prometheus.MustRegister(packetsDropped)
	prometheus.MustRegister(pubsubRequests)
	prometheus.MustRegister(pubsubRequestsDropped)
	prometheus.MustRegister(pubsubRequestsFailed)
	prometheus.MustRegister(pubsubRequestsDuration)
}

// ParameterEndpoint is the mandatory Parameter key indicationg the
// Kaetzchen's endpoint.
const ParameterEndpoint = "endpoint"

// PluginChans maps from Recipient ID to channel.
type PluginChans = map[[sConstants.RecipientIDLength]byte]*channels.InfiniteChannel

// PluginName is the name of a plugin.
type PluginName = string

// PluginParameters maps from parameter key to value.
type PluginParameters = map[PluginName]interface{}

// ServiceMap maps from plugin name to plugin parameters
// and is used by Mix Descriptors which describe Providers
// with plugins. Each plugin can optionally set one or more
// parameters.
type ServiceMap = map[PluginName]PluginParameters

// PluginWorker implements the publish subscribe plugin worker.
type PluginWorker struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	haltOnce    sync.Once
	pluginChans PluginChans
	clients     []*pubsubplugin.Client
	forPKI      ServiceMap
}

// OnSubscribeRequest enqueues the pkt for processing by our thread pool of plugins.
func (k *PluginWorker) OnSubscribeRequest(pkt *packet.Packet) {
	handlerCh, ok := k.pluginChans[pkt.Recipient.ID]
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping PubsubPlugin request: %v", pkt.ID)
		return
	}
	handlerCh.In() <- pkt
}

func (k *PluginWorker) worker(recipient [sConstants.RecipientIDLength]byte, pluginClient pubsubplugin.ServicePlugin) {

	// Kaetzchen delay is our max dwell time.
	maxDwell := time.Duration(k.glue.Config().Debug.KaetzchenDelay) * time.Millisecond

	defer k.haltOnce.Do(k.haltAllClients)

	handlerCh, ok := k.pluginChans[recipient]
	if !ok {
		k.log.Debugf("Failed to find handler. Dropping PubsubPlugin request: %v", recipient)
		pubsubRequestsDropped.Inc()
		return
	}
	ch := handlerCh.Out()

	for {
		var pkt *packet.Packet
		select {
		case <-k.HaltCh():
			k.log.Debugf("Terminating gracefully.")
			return
		case e := <-ch:
			pkt = e.(*packet.Packet)
			if dwellTime := monotime.Now() - pkt.DispatchAt; dwellTime > maxDwell {
				k.log.Debugf("Dropping packet: %v (Spend %v in queue)", pkt.ID, dwellTime)
				packetsDropped.Inc()
				pkt.Dispose()
				continue
			}
		}

		k.processPacket(pkt, pluginClient)
		pubsubRequests.Inc()
	}
}

func (k *PluginWorker) haltAllClients() {
	k.log.Debug("Halting plugin clients.")
	for _, client := range k.clients {
		go client.Halt()
	}
}

func (k *PluginWorker) processPacket(pkt *packet.Packet, pluginClient pubsubplugin.ServicePlugin) {
	pubsubRequestsTimer = prometheus.NewTimer(pubsubRequestsDuration)
	defer pubsubRequestsTimer.ObserveDuration()
	defer pkt.Dispose()

	ct, surbs, err := packet.ParseForwardPacket(pkt)
	if err != nil {
		k.log.Debugf("Dropping Pubsub request: %v (%v)", pkt.ID, err)
		pubsubRequestsDropped.Inc()
		return
	}
	if len(surbs) == 0 {
		k.log.Debugf("Zero SURBs supplied. Dropping Pubsub request: %v (%v)", pkt.ID, err)
		pubsubRequestsDropped.Inc()
		return
	}
	err = pluginClient.OnSubscribe(&pubsubplugin.Subscribe{
		ID:        pkt.ID,
		Payload:   ct,
		SURBCount: len(surbs),
	})
	if err != nil {
		k.log.Debugf("Failed to handle Pubsub request: %v (%v), response: %s", pkt.ID, err, resp)
		return
	}
	if len(resp) == 0 {
		k.log.Debugf("No reply from Pubsub: %v", pkt.ID)
		return
	}

	// Prepend the response header.
	resp = append([]byte{0x01, 0x00}, resp...)
	surb := surbs[0]
	respPkt, err := packet.NewPacketFromSURB(pkt, surb, resp)
	if err != nil {
		k.log.Debugf("Failed to generate SURB-Reply: %v (%v)", pkt.ID, err)
		return
	}

	k.log.Debugf("Handing off newly generated SURB-Reply: %v (Src:%v)", respPkt.ID, pkt.ID)
	k.glue.Scheduler().OnPacket(respPkt)
	return
}

// PubsubForPKI returns the plugins Parameters map for publication in the PKI doc.
func (k *PluginWorker) PubsubForPKI() ServiceMap {
	return k.forPKI
}

// IsPubsub returns true if the given recipient is one of our workers.
func (k *PluginWorker) IsPubsub(recipient [sConstants.RecipientIDLength]byte) bool {
	_, ok := k.pluginChans[recipient]
	return ok
}

func (k *PluginWorker) launch(command string, args []string) (*pubsubplugin.Client, error) {
	k.log.Debugf("Launching plugin: %s", command)
	plugin := pubsubplugin.New(command, k.glue.LogBackend())
	err := plugin.Start(command, args)
	return plugin, err
}

// NewPluginWorker returns a new PluginWorker
func NewPluginWorker(glue glue.Glue) (*PluginWorker, error) {

	pluginWorker := PluginWorker{
		glue:        glue,
		log:         glue.LogBackend().GetLogger("pubsub plugin worker"),
		pluginChans: make(PluginChans),
		clients:     make([]*pubsubplugin.Client, 0),
		forPKI:      make(ServiceMap),
	}

	capaMap := make(map[string]bool)

	for _, pluginConf := range glue.Config().Provider.PubsubPlugin {
		pluginWorker.log.Noticef("Configuring plugin handler for %s", pluginConf.Capability)

		// Ensure no duplicates.
		capa := pluginConf.Capability
		if capa == "" {
			return nil, errors.New("pubsub plugin capability cannot be empty string")
		}
		if pluginConf.Disable {
			pluginWorker.log.Noticef("Skipping disabled Pubsub: '%v'.", capa)
			continue
		}
		if capaMap[capa] {
			return nil, fmt.Errorf("provider: Pubsub '%v' registered more than once", capa)
		}

		// Sanitize the endpoint.
		if pluginConf.Endpoint == "" {
			return nil, fmt.Errorf("provider: Pubsub: '%v' provided no endpoint", capa)
		} else if epNorm, err := precis.UsernameCaseMapped.String(pluginConf.Endpoint); err != nil {
			return nil, fmt.Errorf("provider: Pubsub: '%v' invalid endpoint: %v", capa, err)
		} else if epNorm != pluginConf.Endpoint {
			return nil, fmt.Errorf("provider: Pubsub: '%v' invalid endpoint, not normalized", capa)
		}
		rawEp := []byte(pluginConf.Endpoint)
		if len(rawEp) == 0 || len(rawEp) > sConstants.RecipientIDLength {
			return nil, fmt.Errorf("provider: Pubsub: '%v' invalid endpoint, length out of bounds", capa)
		}

		// Add an infinite channel for this plugin.
		var endpoint [sConstants.RecipientIDLength]byte
		copy(endpoint[:], rawEp)
		pluginWorker.pluginChans[endpoint] = channels.NewInfiniteChannel()

		// Add entry from this plugin for the PKI.
		params := make(map[string]interface{})
		gotParams := false

		// Start the plugin clients.
		for i := 0; i < pluginConf.MaxConcurrency; i++ {
			pluginWorker.log.Noticef("Starting Pubsub plugin client: %s %d", capa, i)

			var args []string
			if len(pluginConf.Config) > 0 {
				args = []string{}
				for key, val := range pluginConf.Config {
					args = append(args, fmt.Sprintf("-%s", key), val.(string))
				}
			}

			pluginClient, err := pluginWorker.launch(pluginConf.Command, args)
			if err != nil {
				pluginWorker.log.Error("Failed to start a plugin client: %s", err)
				return nil, err
			}

			if !gotParams {
				// just once we call the Parameters method on the plugin
				// and use that info to populate our forPKI map which
				// ends up populating the PKI document
				p := pluginClient.GetParameters()
				if p != nil {
					for key, value := range *p {
						params[key] = value
					}
				}
				params[ParameterEndpoint] = pluginConf.Endpoint
				gotParams = true
			}

			// Accumulate a list of all clients to facilitate clean shutdown.
			pluginWorker.clients = append(pluginWorker.clients, pluginClient)

			// Start the workers _after_ we have added all of the entries to pluginChans
			// otherwise the worker() goroutines race this thread.
			defer pluginWorker.Go(func() {
				pluginWorker.worker(endpoint, pluginClient)
			})
		}

		pluginWorker.forPKI[capa] = params
		capaMap[capa] = true
	}

	return &pluginWorker, nil
}
