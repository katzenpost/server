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
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/pubsubplugin"
	"gopkg.in/op/go-logging.v1"
)

type Server struct {
	worker.Worker

	logBackend *log.Backend
	log        *logging.Logger

	listener   net.Listener
	socketFile string

	appMessagesCh chan *pubsubplugin.AppMessages
}

func (s *Server) sendParameters(conn net.Conn) error {
	lenPrefixBuf := make([]byte, 2)
	_, err := io.ReadFull(conn, lenPrefixBuf)
	if err != nil {
		return err
	}
	lenPrefix := pubsubplugin.PrefixLengthDecode(lenPrefixBuf)
	getParamsBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(conn, getParamsBuf)
	if err != nil {
		return err
	}
	_, err = pubsubplugin.GetParametersFromBytes(getParamsBuf)
	if err != nil {
		return err
	}

	params := make(pubsubplugin.Parameters)
	paramsBlob, err := pubsubplugin.ParametersToBytes(&params)
	if err != nil {
		return err
	}
	_, err = conn.Write(paramsBlob)
	return err
}

func (s *Server) readSubscription(conn net.Conn) (*pubsubplugin.Subscribe, error) {
	lenPrefixBuf := make([]byte, 2)
	_, err := io.ReadFull(conn, lenPrefixBuf)
	if err != nil {
		return nil, err
	}
	lenPrefix := pubsubplugin.PrefixLengthDecode(lenPrefixBuf)
	subscribeBuf := make([]byte, lenPrefix)
	_, err = io.ReadFull(conn, subscribeBuf)
	if err != nil {
		return nil, err
	}
	subscribe, err := pubsubplugin.SubscribeFromBytes(subscribeBuf)
	return subscribe, err
}

func (s *Server) perpetualSubscribeReader(conn net.Conn) <-chan *pubsubplugin.Subscribe {
	readCh := make(chan *pubsubplugin.Subscribe)

	s.Go(func() {
		for {
			subscription, err := s.readSubscription(conn)
			if err != nil {
				s.log.Errorf("failure to read new messages from plugin: %s", err)
				s.Halt()
			}
			select {
			case <-s.HaltCh():
				return
			case readCh <- subscription:
			}
		}
	})

	return readCh
}

func (s *Server) worker() {
	conn, err := s.listener.Accept()
	if err != nil {
		s.log.Errorf("error accepting connection: %s", err)
		return
	}
	err = s.sendParameters(conn)
	if err != nil {
		s.log.Errorf("error sending Parameters: %s", err)
		return
	}

	readSubscribeCh := s.perpetualSubscribeReader(conn)

	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("Worker terminating gracefully.")
			return
		case _ = <-readSubscribeCh:
			// XXX FIXME; do something useful with the subscribe request

		case messages := <-s.appMessagesCh:
			messagesBlob, err := messages.ToBytes()
			if err != nil {
				s.log.Errorf("failed to deserialized AppMessages: %s", err)
				continue
			}
			messagesBlob = pubsubplugin.PrefixLengthEncode(messagesBlob)
			_, err = conn.Write(messagesBlob)
			if err != nil {
				s.log.Errorf("failed to write AppMessages to socket: %s", err)
				continue
			}
		}
	}
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

func New(name, socketFile, logDir, logLevel string) (*Server, error) {
	s := &Server{
		socketFile:    socketFile,
		appMessagesCh: make(chan *pubsubplugin.AppMessages),
	}
	err := s.ensureLogDir(logDir)
	if err != nil {
		return nil, err
	}
	logFile := path.Join(logDir, fmt.Sprintf("%s.%d.log", name, os.Getpid()))
	err = s.initLogging(name, logFile, logLevel)
	if err != nil {
		return nil, err
	}
	s.log.Debug("starting listener")
	err = s.setupListener(name)
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
