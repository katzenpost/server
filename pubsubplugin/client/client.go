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

// Package pubsubplugin client is the client module a plugin system allowing mix network services
// to be added in any language. It implements a publish subscribe interface.
//
package client

import (
	"bufio"
	"io"
	"net"
	"os/exec"
	"syscall"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/pubsubplugin/common"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

const unixSocketNetwork = "unix"

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
	params        *common.Parameters
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

func (c *Client) readAppMessages() (*common.AppMessages, error) {
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
	newMessages, err := common.AppMessagesFromBytes(responseBuf)
	if err != nil {
		return nil, err
	}
	return newMessages, nil
}

func (c *Client) perpetualReader() <-chan common.AppMessages {
	readCh := make(chan common.AppMessages)

	c.Go(func() {
		for {
			newMessages, err := c.readAppMessages()
			if err != nil {
				c.log.Errorf("failure to read new messages from plugin: %s", err)
				c.Halt()
			}
			select {
			case <-c.HaltCh():
				return
			case readCh <- *newMessages:
			}
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

// GetAppMessagesChan returns an readonly channel where the
// application messages will be written to.
func (c *Client) GetAppMessagesChan() <-chan interface{} {
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

func (c *Client) getParameters() (*common.Parameters, error) {
	// write GetParameters "command"
	rawGetParams, err := common.GetParametersToBytes()
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
	responseParams, err := common.ParametersFromBytes(responseBuf)
	if err != nil {
		return nil, err
	}
	return responseParams, nil
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

func (c *Client) Unsubscribe(subscriptionID [common.SubscriptionIDLength]byte) error {
	u := &common.Unsubscribe{
		SubscriptionID: subscriptionID,
	}
	serializedUnsubscribe, err := u.ToBytes()
	if err != nil {
		return err
	}
	serializedUnsubscribe = common.PrefixLengthEncode(serializedUnsubscribe)
	_, err = c.conn.Write(serializedUnsubscribe)
	return err
}

// Subscribe send a subscription request to the plugin using our
// length prefixed CBOR over Unix domain socket protocol.
func (c *Client) Subscribe(subscribe *common.Subscribe) error {
	serializedSubscribe, err := subscribe.ToBytes()
	if err != nil {
		return err
	}
	serializedSubscribe = common.PrefixLengthEncode(serializedSubscribe)
	_, err = c.conn.Write(serializedSubscribe)
	return err
}

// GetParameters are used in Mix Descriptor publication to give
// service clients more information about the service. Not
// plugins will need to use this feature.
func (c *Client) GetParameters() *common.Parameters {
	return c.params
}
