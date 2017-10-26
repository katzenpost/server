// config.go - Katzenpost server configuration.
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

// Package config provides the Katzenpost server configuration.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/katzenpost/core/sphinx/constants"
	"github.com/pelletier/go-toml"
)

const (
	defaultAddress          = ":3219"
	defaultLogLevel         = "NOTICE"
	defaultSchedulerSlack   = 10        // 10 ms.
	defaultSendSlack        = 50        // 50 ms.
	defaultConnectTimeout   = 60 * 1000 // 60 sec.
	defaultHandshakeTimeout = 30 * 1000 // 30 sec.
)

var (
	defaultDebug   Debug
	defaultLogging = Logging{
		Disable: false,
		File:    "",
		Level:   defaultLogLevel,
	}
)

// Server is the Katzenpost server configuration.
type Server struct {
	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

	// Addresses are the IP address/port combinations that the server will bind
	// to for incoming connections.
	Addresses []string

	// DataDir is the absolute path to the server's state files.
	DataDir string

	// IsProvider specifies if the server is a provider (vs a mix).
	IsProvider bool
}

func (sCfg *Server) validate() error {
	if sCfg.Identifier == "" {
		return fmt.Errorf("config: Server: Identifier is not set")
	} else if len(sCfg.Identifier) > constants.NodeIDLength {
		return fmt.Errorf("config: Server: Identifier '%v' exceeds max length", sCfg.Identifier)
	}

	if sCfg.Addresses != nil {
		for _, v := range sCfg.Addresses {
			host, _, err := net.SplitHostPort(v)
			if err != nil {
				return err
			}
			if net.ParseIP(host) == nil {
				return fmt.Errorf("config: Server: Address '%v' is not an IP", host)
			}
		}
	} else {
		// XXX: Enumerate the addresses, this won't work without other
		// trickery, since the IP(s) of the node needs to be a known
		// quantity for the purpose of publishing directory documents.
		sCfg.Addresses = []string{defaultAddress}
	}
	if !filepath.IsAbs(sCfg.DataDir) {
		return fmt.Errorf("config: Server: DataDir '%v' is not an absolute path", sCfg.DataDir)
	}
	return nil
}

// Debug is the Katzenpost server debug configuration.
type Debug struct {
	// DisableKeyRotation disables the mix key rotation.
	DisableKeyRotation bool

	// DisableMixAuthentication disables the mix incoming peer authentication.
	DisableMixAuthentication bool

	// NumSphinxWorkers specifies the number of worker instances to use for
	// inbound Sphinx packet processing.
	NumSphinxWorkers int

	// SchedulerSlack is the maximum allowed scheduler slack due to queueing
	// and or processing in milliseconds.
	SchedulerSlack int

	// SendSlack is the maximum allowed send queue slack due to queueing and
	// or congestion in milliseconds.
	SendSlack int

	// ConnectTimeout specifies the maximum time a  connection can take to
	// establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// HandshakeTimeout specifies the maximum time a connection can take for a
	// link protocol handshake in milliseconds.
	HandshakeTimeout int

	// GenerateOnly halts and cleans up the server right after key generation.
	GenerateOnly bool
}

// IsUnsafe returns true iff any debug options that destroy security are set.
func (dCfg *Debug) IsUnsafe() bool {
	return dCfg.DisableKeyRotation || dCfg.DisableMixAuthentication
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.NumSphinxWorkers <= 0 {
		// Pick a sane default for the number of workers.
		//
		// TODO/perf: This should detect the number of physical cores, since
		// the AES-NI unit is a per-core resource.
		dCfg.NumSphinxWorkers = runtime.NumCPU()
	}
	if dCfg.SchedulerSlack < defaultSchedulerSlack {
		// TODO/perf: Tune this.
		dCfg.SchedulerSlack = defaultSchedulerSlack
	}
	if dCfg.SendSlack < defaultSendSlack {
		// TODO/perf: Tune this, probably upwards to be more tollerant of poor
		// networking conditions.
		dCfg.SendSlack = defaultSendSlack
	}
	if dCfg.ConnectTimeout <= 0 {
		dCfg.ConnectTimeout = defaultConnectTimeout
	}
	if dCfg.HandshakeTimeout <= 0 {
		dCfg.HandshakeTimeout = defaultHandshakeTimeout
	}
}

// Logging is the Katzenpost server logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

func (lCfg *Logging) validate() error {
	lvl := strings.ToUpper(lCfg.Level)
	switch lvl {
	case "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
	case "":
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

// Authentication is the Katzenpost provider authentication configuration.
type Authentication struct {
}

// Config is the top level Katzenpost server configuration.
type Config struct {
	Server         *Server
	Logging        *Logging
	Authentication *Authentication
	// XXX: PKI.

	Debug *Debug
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)
	if err := toml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}

	// The Server section is mandatory, everything else is optional.
	if cfg.Server == nil {
		return nil, errors.New("config: No Server block was present")
	}
	if cfg.Debug == nil {
		cfg.Debug = &defaultDebug
	}
	if cfg.Logging == nil {
		cfg.Logging = &defaultLogging
	}

	// Perform basic validation.
	if err := cfg.Server.validate(); err != nil {
		return nil, err
	}
	if cfg.Server.IsProvider {
		if cfg.Debug.DisableMixAuthentication {
			return nil, errors.New("config: DisableMixAuthentication set when not a Mix")
		}
		// XXX/provider: Do something here.
	} else if cfg.Authentication != nil {
		return nil, errors.New("config: Authentication block when not a Provider")
	}
	if err := cfg.Logging.validate(); err != nil {
		return nil, err
	}
	cfg.Debug.applyDefaults()

	return cfg, nil
}

// LoadFile loads, parses and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
