// dialer.go - client plugin dialer, tracks multiple connections to a plugin
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
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"syscall"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/server/pubsubplugin/common"
	"gopkg.in/op/go-logging.v1"
)

const unixSocketNetwork = "unix"

// Dialer handles the launching and subsequent multiple dialings of a given plugin.
type Dialer struct {
	sync.RWMutex

	logBackend *log.Backend
	log        *logging.Logger

	// for sending subscribe/unsubscribe commands to the plugin
	outgoingCh chan interface{}

	// for receiving AppMessages from the plugin
	incomingCh chan *common.AppMessages

	conns      []*outgoingConn
	cmd        *exec.Cmd
	socketPath string
	params     *common.Parameters

	haltOnce sync.Once
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func New(command string, logBackend *log.Backend) *Dialer {
	return &Dialer{
		logBackend: logBackend,
		log:        logBackend.GetLogger(command),

		outgoingCh: make(chan interface{}),
		incomingCh: make(chan *common.AppMessages),
		conns:      make([]*outgoingConn, 0),
	}
}

func (d *Dialer) IncomingCh() chan *common.AppMessages {
	return d.incomingCh
}

// Halt halts all of the outgoing connections and halts
// the execution of the plugin application.
func (d *Dialer) Halt() {
	d.haltOnce.Do(d.doHalt)
}

func (d *Dialer) doHalt() {
	d.RLock()
	defer d.RUnlock()
	for _, outgoingConn := range d.conns {
		outgoingConn.Halt()
	}
	d.cmd.Process.Signal(syscall.SIGTERM)
	err := d.cmd.Wait()
	if err != nil {
		d.log.Errorf("Publish-subscript plugin worker, command halt exec error: %s\n", err)
	}
}

func (d *Dialer) logPluginStderr(stderr io.ReadCloser) {
	logWriter := d.logBackend.GetLogWriter(d.cmd.Path, "DEBUG")
	_, err := io.Copy(logWriter, stderr)
	if err != nil {
		d.log.Errorf("Failed to proxy pubsubplugin stderr to DEBUG log: %s", err)
	}
	d.Halt()
}

// Launch executes the given command and args, reading the unix socket path
// from STDOUT and saving it for later use when dialing the socket.
func (d *Dialer) Launch(command string, args []string) error {
	// exec plugin
	d.cmd = exec.Command(command, args...)
	stdout, err := d.cmd.StdoutPipe()
	if err != nil {
		d.log.Debugf("pipe failure: %s", err)
		return err
	}
	stderr, err := d.cmd.StderrPipe()
	if err != nil {
		d.log.Debugf("pipe failure: %s", err)
		return err
	}
	err = d.cmd.Start()
	if err != nil {
		d.log.Debugf("failed to exec: %s", err)
		return err
	}

	// proxy stderr to our debug log
	go d.logPluginStderr(stderr)

	// read and decode plugin stdout
	stdoutScanner := bufio.NewScanner(stdout)
	stdoutScanner.Scan()
	d.socketPath = stdoutScanner.Text()
	d.log.Debugf("plugin socket path:'%s'\n", d.socketPath)
	return nil
}

// Dial dials the unix socket that was recorded during Launch.
func (d *Dialer) Dial() error {
	conn, err := net.Dial(unixSocketNetwork, d.socketPath)
	if err != nil {
		d.log.Debugf("unix socket connect failure: %s", err)
		return err
	}
	d.onNewConn(conn)
	return nil
}

func (d *Dialer) ensureParameters(outgoingConn *outgoingConn) error {
	if d.params == nil {
		d.log.Debug("requesting plugin Parameters for Mix Descriptor publication")
		var err error
		d.params, err = outgoingConn.getParameters()
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Dialer) onNewConn(conn net.Conn) {
	connLog := d.logBackend.GetLogger(fmt.Sprintf("%s connection %d", d.cmd, len(d.conns)+1))
	outConn := newOutgoingConn(d, conn, connLog)

	err := d.ensureParameters(outConn)
	if err != nil {
		d.log.Error("failed to acquire plugin parameters, giving up on plugin connection")
		return
	}

	d.Lock()
	defer func() {
		d.Unlock()
		outConn.Go(outConn.worker)
	}()
	d.conns = append(d.conns, outConn)
}

// Parameters returns the Parameters whcih are used in Mix Descriptor
// publication to give service clients more information about the service.
func (d *Dialer) Parameters() *common.Parameters {
	return d.params
}

// Unsubscribe sends a subscription request to the plugin over
// the Unix domain socket protocol.
func (d *Dialer) Unsubscribe(subscriptionID [common.SubscriptionIDLength]byte) {
	u := &common.Unsubscribe{
		SubscriptionID: subscriptionID,
	}
	d.outgoingCh <- u
}

// Subscribe sends a subscription request to the plugin over
// the Unix domain socket protocol.
func (d *Dialer) Subscribe(subscribe *common.Subscribe) {
	d.outgoingCh <- subscribe
}
