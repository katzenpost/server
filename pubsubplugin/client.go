// client.go - client of the pubsub plugin system for remote mixnet services
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

// Package pubsubplugin is a plugin system allowing mix network services
// to be added in any language. It implements a publish subscribe interface.
//
package pubsubplugin

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"syscall"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

const (
	// SubscriptionIDLength is the length of the Subscription ID.
	SubscriptionIDLength = 8

	// SpoolIDLength is the length of the spool identity.
	SpoolIDLength = 8

	unixSocketNetwork = "unix"
)

// Subscribe is the struct type used to establish a subscription with
// the plugin.
type Subscribe struct {
	// PacketID is the packet identity.
	PacketID uint64

	// SURBCount is the number of SURBs available to this subscription.
	SURBCount uint8

	// SubscriptionID is the server generated subscription identity.
	SubscriptionID [SubscriptionIDLength]byte

	// SpoolID is the spool identity.
	SpoolID [SpoolIDLength]byte

	// LastSpoolIndex is the last spool index which was received by the client.
	LastSpoolIndex uint64

	// Payload is the payload to be delivered to the spool service plugin.
	Payload []byte
}

// NewMessages is the struct type used by the application plugin to
// send new messages to the server and eventually the subscribing client.
type NewMessages struct {
	// Messages should contain one or more spool messages.
	Messages []SpoolMessage
}

// SpoolMessage is a spool message from the application plugin.
type SpoolMessage struct {
	// Index is the index value from whence the message came from.
	Index uint64

	// Payload contains the actual spool message contents.
	Payload []byte
}

// Parameters is an optional mapping that plugins can publish, these get
// advertised to clients in the MixDescriptor.
// The output of GetParameters() ends up being published in a map
// associating with the service names to service parameters map.
// This information is part of the Mix Descriptor which is defined here:
// https://github.com/katzenpost/core/blob/master/pki/pki.go
type Parameters map[string]string

// GetParameters is used for querying the plugin over the unix socket
// to get the dynamic parameters after the plugin is started.
type GetParameters struct{}

// ServicePlugin is the interface that we expose for external
// plugins to implement. This is similar to the internal Kaetzchen
// interface defined in:
// github.com/katzenpost/server/internal/provider/kaetzchen/kaetzchen.go
type ServicePlugin interface {
	// OnSubscribe is the method that is called when the Provider receives
	// a subscription request designated for a particular plugin agent.
	OnSubscribe(*Subscribe) error

	// GetNewMessagesChan returns an readonly channel where the
	// application messages will be written to.
	GetNewMessagesChan() <-chan interface{}

	// Parameters returns the agent's paramenters for publication in
	// the Provider's descriptor.
	GetParameters() *Parameters

	// Halt stops the plugin.
	Halt()
}

// Client acts as a client interacting with one or more plugins.
// The Client type is composite with Worker and therefore
// has a Halt method. Client implements this interface
// and proxies data between this mix server and the
// external plugin program.
type Client struct {
	worker.Worker

	logBackend    *log.Backend
	log           *logging.Logger
	conn          net.Conn
	cmd           *exec.Cmd
	socketPath    string
	params        *Parameters
	newMessagesCh *channels.InfiniteChannel
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func New(command string, logBackend *log.Backend) *Client {
	return &Client{
		logBackend:    logBackend,
		log:           logBackend.GetLogger(command),
		conn:          nil,
		newMessagesCh: channels.NewInfiniteChannel(),
	}
}

// Start execs the plugin and starts a worker thread to listen
// on the halt chan sends a TERM signal to the plugin if the shutdown
// even is dispatched.
func (c *Client) Start(command string, args []string) error {
	err := c.launch(command, args)
	if err != nil {
		return err
	}
	c.Go(c.worker)
	return nil
}

func (c *Client) decodeNewMessages(rawNewMessages []byte) (*NewMessages, error) {
	newMessages := NewMessages{}
	err := cbor.Unmarshal(rawNewMessages, &newMessages)
	if err != nil {
		return nil, err
	}
	return &newMessages, nil
}

func (c *Client) readNewMessages() (*NewMessages, error) {
	lenPrefixBuf := make([]byte, 2)
	_, err := io.ReadFull(c.conn, lenPrefixBuf)
	if err != nil {
		return nil, err
	}
	lenPrefix := binary.BigEndian.Uint16(lenPrefixBuf)
	responseBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(c.conn, responseBuf)
	if err != nil {
		return nil, err
	}
	newMessages, err := c.decodeNewMessages(responseBuf)
	if err != nil {
		return nil, err
	}
	return newMessages, nil
}

func (c *Client) perpetualReader() <-chan NewMessages {
	readCh := make(chan NewMessages)

	c.Go(func() {
		for {
			newMessages, err := c.readNewMessages()
			if err != nil {
				c.log.Errorf("failure to read new messages from plugin: %s", err)
				c.Halt()
			}
			readCh <- *newMessages
		}
	})

	return readCh
}

func (c *Client) worker() {
	defer func() {
		c.cmd.Process.Signal(syscall.SIGTERM)
		err := c.cmd.Wait()
		if err != nil {
			c.log.Errorf("CBOR plugin worker, command exec error: %s\n", err)
		}
	}()
	readChan := c.perpetualReader()
	for {
		select {
		case <-c.HaltCh():
			return
		case message := <-readChan:
			c.newMessagesCh.In() <- message
		}
	}
}

// GetNewMessagesChan returns an readonly channel where the
// application messages will be written to.
func (c *Client) GetNewMessagesChan() <-chan interface{} {
	return c.newMessagesCh.Out()
}

func (c *Client) logPluginStderr(stderr io.ReadCloser) {
	logWriter := c.logBackend.GetLogWriter(c.cmd.Path, "DEBUG")
	_, err := io.Copy(logWriter, stderr)
	if err != nil {
		c.log.Errorf("Failed to proxy pubsubplugin stderr to DEBUG log: %s", err)
	}
	c.Halt()
}

func (c *Client) setupUnixSocketClient(socketPath string) error {
	var err error
	c.conn, err = net.Dial(unixSocketNetwork, socketPath)
	return err
}

func (c *Client) getParameters() (*Parameters, error) {
	// write GetParameters "command"
	rawGetParams, err := cbor.Marshal(&GetParameters{})
	if err != nil {
		return nil, err
	}
	lenPrefixBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefixBuf, uint16(len(rawGetParams)))
	rawGetParams = append(lenPrefixBuf, rawGetParams...)
	_, err = c.conn.Write(rawGetParams)
	if err != nil {
		return nil, err
	}

	// read response
	lenPrefixBuf = make([]byte, 2)
	_, err = io.ReadFull(c.conn, lenPrefixBuf)
	if err != nil {
		return nil, err
	}
	lenPrefix := binary.BigEndian.Uint16(lenPrefixBuf)
	responseBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(c.conn, responseBuf)
	if err != nil {
		return nil, err
	}
	responseParams := make(Parameters)
	err = cbor.Unmarshal(responseBuf, &responseParams)
	if err != nil {
		return nil, err
	}
	return &responseParams, nil
}

func (c *Client) launch(command string, args []string) error {
	// exec plugin
	c.cmd = exec.Command(command, args...)
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	err = c.cmd.Start()
	if err != nil {
		c.log.Debugf("failed to exec: %s", err)
		return err
	}

	// proxy stderr to our debug log
	c.Go(func() {
		c.logPluginStderr(stderr)
	})

	// read and decode plugin stdout
	stdoutScanner := bufio.NewScanner(stdout)
	stdoutScanner.Scan()
	c.socketPath = stdoutScanner.Text()
	c.log.Debugf("plugin socket path:'%s'\n", c.socketPath)
	err = c.setupUnixSocketClient(c.socketPath)
	if err != nil {
		c.log.Debugf("unix socket connect failure: %s", err)
		return err
	}

	// get plugin parameters if any
	c.log.Debug("requesting plugin Parameters for Mix Descriptor publication...")
	responseParams, err := c.getParameters()
	if err != nil {
		c.log.Debugf("failure to acquire plugin Parameters: %s", err)
		c.Halt()
		return err
	}
	c.params = responseParams
	c.log.Debug("finished launching plugin.")
	return nil
}

// OnSubscribe send a subscription request to the plugin using our
// length prefixed CBOR over Unix domain socket protocol.
func (c *Client) OnSubscribe(subscribe *Subscribe) error {
	serializedSubscribe, err := cbor.Marshal(subscribe)
	if err != nil {
		return err
	}
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(serializedSubscribe)))
	serializedSubscribe = append(lenPrefix, serializedSubscribe...)
	_, err = c.conn.Write(serializedSubscribe)
	return err
}

// GetParameters are used in Mix Descriptor publication to give
// service clients more information about the service. Not
// plugins will need to use this feature.
func (c *Client) GetParameters() *Parameters {
	return c.params
}
