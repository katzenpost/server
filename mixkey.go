// mixkey.go - Katzenpost server mix key store.
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

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/server/internal/mixkey"
	"github.com/op/go-logging"
)

const debugStaticEpoch = 0

type mixKeys struct {
	sync.Mutex

	s   *Server
	log *logging.Logger

	keys map[uint64]*mixkey.MixKey
}

func (m *mixKeys) init() error {
	if m.s.cfg.Debug.DisableKeyRotation {
		// If key rotation is disabled via the debug parameter, then
		// use a static epoch for the purpose of identifying the internal
		// key.
		k, err := mixkey.New(m.s.cfg.Server.DataDir, debugStaticEpoch)
		if err != nil {
			return err
		}
		m.keys[debugStaticEpoch] = k

		m.log.Warning("Static mix key is used, there will be no forward secrecy.")

		return nil
	}

	// Generate/load the initial set of keys.
	//
	// TODO: In theory this should also try to load the previous epoch's key
	// if the current time is in the clock skew grace period.  But it may not
	// matter much in practice.
	epoch, _, _ := epochtime.Now()
	for t := epoch; t < epoch+3; t++ {
		k, err := mixkey.New(m.s.cfg.Server.DataDir, t)
		if err != nil {
			// Clean up whatever keys that may have succeded.
			for idx, v := range m.keys {
				v.Deref()
				delete(m.keys, idx)
			}
			return err
		}
		k.SetUnlinkIfExpired(true)
		m.keys[t] = k
	}

	// TODO: Clean up stale mix keys hanging around the data directory.

	return nil
}

func (m *mixKeys) shadow(dst map[uint64]*mixkey.MixKey) {
	m.Lock()
	defer m.Unlock()

	// Purge the keys no longer listed from dst.
	for k, v := range dst {
		if _, ok := m.keys[k]; !ok {
			v.Deref()
			delete(dst, k)
		}
	}

	// Add newly listed keys to dst and bump up the refcount.
	for k, v := range m.keys {
		if _, ok := dst[k]; !ok {
			v.Ref()
			dst[k] = v
		}
	}
}

func (m *mixKeys) halt() {
	m.Lock()
	defer m.Unlock()

	for k, v := range m.keys {
		v.Deref()
		delete(m.keys, k)
	}
}

func newMixKeys(s *Server) (*mixKeys, error) {
	m := new(mixKeys)
	m.s = s
	m.log = s.newLogger("mixkeys")
	m.keys = make(map[uint64]*mixkey.MixKey)
	if err := m.init(); err != nil {
		return nil, err
	}

	return m, nil
}
