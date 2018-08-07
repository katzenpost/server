// grpc.go - Katzenpost grpc plugins.
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
	"github.com/katzenpost/server/common-plugin/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	Impl KaetzchenPluginInterface
}

func (m *GRPCServer) OnRequest(ctx context.Context, request *proto.Request) (*proto.Response, error) {
	resp, err := m.Impl.OnRequest(request.Payload, request.HasSURB)
	return &proto.Response{
		Payload: resp,
	}, err
}

type GRPCClient struct {
	client proto.KaetzchenClient
}

func (m *GRPCClient) OnRequest(request []byte, hasSURB bool) ([]byte, error) {
	resp, err := m.client.OnRequest(context.Background(), &proto.Request{
		Payload: request,
		HasSURB: hasSURB,
	})
	if err == nil {
		return resp.Payload, err
	} else {
		return nil, err
	}
}
