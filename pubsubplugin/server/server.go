// server.go - Publish subscribe server module for writing plugins.
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

package server

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/pubsubplugin/common"
	"gopkg.in/op/go-logging.v1"
)

// Spool is an interface for spool implementations which
// will handle publishing new spool content to spool subscribers.
type Spool interface {
	// Subscribe creates a new spool subscription.
	Subscribe(subscriptionID *common.SubscriptionID, spoolID *common.SpoolID, lastSpoolIndex uint64) error

	// Unsubscribe removes an existing spool subscription.
	Unsubscribe(subscriptionID *common.SubscriptionID) error
}

// Config is used to configure a new Server instance.
type Config struct {
	// Name is the name of the application service.
	Name string

	// Parameters are the application service specified parameters which are advertized in the
	// Katzenpost PKI document.
	Parameters *common.Parameters

	// LogDir is the logging directory.
	LogDir string

	// LogLevel is the log level and is set to one of: ERROR, WARNING, NOTICE, INFO, DEBUG, CRITICAL.
	LogLevel string

	// Spool is the implementation of our Spool interface.
	Spool Spool

	// AppMessagesCh is the application messages channel which is used by the application to send
	// messages to the mix server for transit over the mix network to the destination client.
	AppMessagesCh chan *common.AppMessages
}

func validateConfig(config *Config) error {
	if config == nil {
		return errors.New("config must not be nil")
	}
	if config.Name == "" {
		return errors.New("config.Name must not be empty")
	}
	if config.Parameters == nil {
		return errors.New("config.Parameters must not be nil")
	}
	if config.LogDir == "" {
		return errors.New("config.LogDir must not be empty")
	}
	if config.LogLevel == "" {
		return errors.New("config.LogLevel must not be empty")
	}
	if config.Spool == nil {
		return errors.New("config.Spool must not be nil")
	}
	if config.AppMessagesCh == nil {
		return errors.New("config.AppMessagesCh must not be nil")
	}
	return nil
}

// Server is used by applications to implement the application plugin which listens
// for connections from the mix server over a unix domain socket. Server handles the
// management of this unix domain socket as well as the wire protocol used.
type Server struct {
	worker.Worker

	logBackend *log.Backend
	log        *logging.Logger

	listener   net.Listener
	socketFile string

	params        *common.Parameters
	appMessagesCh chan *common.AppMessages
	spool         Spool
}

func (s *Server) sendParameters(conn net.Conn) error {
	e := &common.EgressUnixSocketCommand{
		Parameters: s.params,
	}
	paramsBlob, err := e.ToBytes()
	if err != nil {
		return err
	}
	paramsBlob = common.PrefixLengthEncode(paramsBlob)
	_, err = conn.Write(paramsBlob)
	return err
}

func (s *Server) readIngressCommands(conn net.Conn) (*common.IngressUnixSocketCommand, error) {
	lenPrefixBuf := make([]byte, 2)
	_, err := io.ReadFull(conn, lenPrefixBuf)
	if err != nil {
		return nil, err
	}
	lenPrefix := common.PrefixLengthDecode(lenPrefixBuf)
	cmdBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(conn, cmdBuf)
	if err != nil {
		return nil, err
	}
	ingressCmd, err := common.IngressUnixSocketCommandFromBytes(cmdBuf)
	return ingressCmd, err
}

func (s *Server) perpetualCommandReader(conn net.Conn) <-chan *common.IngressUnixSocketCommand {
	readCh := make(chan *common.IngressUnixSocketCommand)

	s.Go(func() {
		for {
			cmd, err := s.readIngressCommands(conn)
			if err != nil {
				s.log.Errorf("failure to read new messages from plugin: %s", err)
				return
			}
			select {
			case <-s.HaltCh():
				return
			case readCh <- cmd:
			}
		}
	})

	return readCh
}

func (s *Server) connectionWorker(conn net.Conn) {
	readCmdCh := s.perpetualCommandReader(conn)

	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("Worker terminating gracefully.")
			return
		case cmd := <-readCmdCh:
			if cmd.GetParameters != nil {
				s.sendParameters(conn)
				continue
			}
			if cmd.Subscribe != nil {
				s.spool.Subscribe(&cmd.Subscribe.SubscriptionID, &cmd.Subscribe.SpoolID, cmd.Subscribe.LastSpoolIndex)
				continue
			}
			if cmd.Unsubscribe != nil {
				s.spool.Unsubscribe(&cmd.Subscribe.SubscriptionID)
				continue
			}
		case messages := <-s.appMessagesCh:
			e := &common.EgressUnixSocketCommand{
				AppMessages: messages,
			}
			messagesBlob, err := e.ToBytes()
			if err != nil {
				s.log.Errorf("failed to serialize app messages: %s", err)
				continue
			}
			messagesBlob = common.PrefixLengthEncode(messagesBlob)
			_, err = conn.Write(messagesBlob)
			if err != nil {
				s.log.Errorf("failed to write AppMessages to socket: %s", err)
				continue
			}
		}
	}
}

func (s *Server) worker() {
	conn, err := s.listener.Accept()
	if err != nil {
		s.log.Errorf("error accepting connection: %s", err)
		return
	}
	s.Go(func() {
		s.connectionWorker(conn)
	})
}

func (s *Server) setupListener(name string) error {
	tmpDir, err := ioutil.TempDir("", name)
	if err != nil {
		return err
	}
	s.socketFile = filepath.Join(tmpDir, fmt.Sprintf("%s.socket", name))
	s.listener, err = net.Listen("unix", s.socketFile)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) initLogging(name, logFile, logLevel string) error {
	var err error
	logDisable := false
	s.logBackend, err = log.New(logFile, logLevel, logDisable)
	if err != nil {
		return err
	}
	s.log = s.logBackend.GetLogger(name)
	return nil
}

func (s *Server) ensureLogDir(logDir string) error {
	stat, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("Log directory '%s' doesn't exist.", logDir)
	}
	if !stat.IsDir() {
		return fmt.Errorf("Log directory '%s' must be a directory.", logDir)
	}
	return nil
}

// New creates a new Server instance and starts immediately listening for new connections.
func New(config *Config) (*Server, error) {
	err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	s := &Server{
		params:        config.Parameters,
		appMessagesCh: config.AppMessagesCh,
		spool:         config.Spool,
	}
	err = s.ensureLogDir(config.LogDir)
	if err != nil {
		return nil, err
	}
	logFile := path.Join(config.LogDir, fmt.Sprintf("%s.%d.log", config.Name, os.Getpid()))
	err = s.initLogging(config.Name, logFile, config.LogLevel)
	if err != nil {
		return nil, err
	}
	s.log.Debug("starting listener")
	err = s.setupListener(config.Name)
	if err != nil {
		return nil, err
	}
	fmt.Printf("%s\n", s.socketFile)
	s.Go(s.worker)
	go func() {
		<-s.HaltCh()
		os.Remove(s.socketFile)
	}()
	return s, nil
}
