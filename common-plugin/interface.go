// kaetzchen.go - Katzenpost provider auto-responder agents.
// Copyright (C) 2018  David Stainton.
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

package plugin

import (
	scontext "context"

	"github.com/hashicorp/go-plugin"
	"github.com/katzenpost/server/common-plugin/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}

type KaetzchenPluginInterface interface {
	OnRequest(request string) (string, error)
}

type GRPCServer struct {
	Impl KaetzchenPluginInterface
}

func (m *GRPCServer) OnRequest(ctx context.Context, request *proto.Request) (*proto.Response, error) {
	resp, err := m.Impl.OnRequest(request.Payload)
	return &proto.Response{
		Payload: resp,
	}, err
}

type GRPCClient struct {
	client proto.KaetzchenClient
}

func (m *GRPCClient) OnRequest(request string) (string, error) {
	resp, err := m.client.OnRequest(context.Background(), &proto.Request{
		Payload: request,
	})
	return resp.Payload, err
}

// This is the implementation of plugin.Plugin so we can serve/consume this.
// We also implement GRPCPlugin so that this plugin can be served over
// gRPC.
type KaetzchenPlugin struct {
	plugin.NetRPCUnsupportedPlugin // XXX do we need this composite type?
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl KaetzchenPluginInterface
}

func (p *KaetzchenPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterKaetzchenServer(s, &GRPCServer{
		Impl: p.Impl,
	})
	return nil
}

func (p *KaetzchenPlugin) GRPCClient(ctx scontext.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewKaetzchenClient(c),
	}, nil
}

var _ plugin.GRPCPlugin = &KaetzchenPlugin{}
