// packet_test.go - Katzenpost server packet structure tests.
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

// Package packet implements the Katzenpost server side packet structure.
package packet

import (
	"testing"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/sphinx"
	"github.com/stretchr/testify/require"
)

func TestParseForwardPacket(t *testing.T) {
	require := require.New(t)

	// test that wrong payload size is an error
	wrongPayload := [constants.ForwardPayloadLength + 123]byte{}
	pkt := &Packet{
		Payload: wrongPayload[:],
	}
	_, _, err := ParseForwardPacket(pkt)
	require.Error(err)

	// test that the wrong reserved value is an error
	payload := [constants.ForwardPayloadLength]byte{}
	pkt = &Packet{
		Payload: payload[:],
	}
	pkt.Payload[1] = byte(1)
	_, _, err = ParseForwardPacket(pkt)
	require.Error(err)

	// test that an invalid SURB count is an error
	payload = [constants.ForwardPayloadLength]byte{}
	pkt = &Packet{
		Payload: payload[:],
	}
	pkt.Payload[0] = byte(255)
	_, _, err = ParseForwardPacket(pkt)
	require.Error(err)

	// test that an invalid SURB count is an error
	payload = [constants.ForwardPayloadLength]byte{}
	pkt = &Packet{
		Payload: payload[:],
	}
	pkt.Payload[0] = byte(93)
	_, _, err = ParseForwardPacket(pkt)
	require.Error(err)

	// test that a large SURB count is OK
	payload = [constants.ForwardPayloadLength]byte{}
	pkt = &Packet{
		Payload: payload[:],
	}
	pkt.Payload[0] = byte(92)
	ct, surbs, err := ParseForwardPacket(pkt)
	require.NoError(err)
	require.Equal(92, len(surbs))
	require.Equal((constants.ForwardPayloadLength-constants.SphinxPlaintextHeaderLength)-(92*sphinx.SURBLength), len(ct))
}
