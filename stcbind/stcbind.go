// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package stcbind implements a stc testbed binding, backed by a stc rest server.
package stcbind

import (
	"fmt"
	"time"

	"github.com/pborman/uuid"
	"golang.org/x/net/context"

	log "github.com/golang/glog"
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/ondatra/binding"
	"github.com/openconfig/ondatra/internal/testbed"
	opb "github.com/openconfig/ondatra/proto"
	"google.golang.org/grpc"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

func Init() (binding.Binding, error) {
	return Setup(), nil
}

// Setup initializes Ondatra with a new  binding, initializes the testbed
// to an unreserved state, and returns the  binding for further stubbing.
func Setup() *StcBind {
	stcbind := new(StcBind)
	testbed.SetBinding(stcbind)
	return stcbind.WithReservation(nil)
}

var _ binding.Binding = (*StcBind)(nil)

// ServiceDUT is a DUT that contains a service map.
type ServiceDUT struct {
	*binding.AbstractDUT
}

type deviceResolution struct {
	dims *binding.Dims
}

// Binding is a binding.Binding implementation comprised of stubs.

type StcBind struct {
}

func (b *StcBind) resolveDUT(dev *opb.Device) (*ServiceDUT, error) {
	dr, err := b.resolveDevice(dev)
	if err != nil {
		return nil, err
	}
	return &ServiceDUT{
		AbstractDUT: &binding.AbstractDUT{Dims: dr.dims},
	}, nil
}

func (b *StcBind) resolveATE(dev *opb.Device) (*ServiceATE, error) {
	dr, err := b.resolveDevice(dev)
	if err != nil {
		return nil, err
	}
	return &ServiceATE{
		AbstractATE: &binding.AbstractATE{Dims: dr.dims},
	}, nil
}

func (b *StcBind) resolveDevice(dev *opb.Device) (*deviceResolution, error) {

	log.Error(dev.String())
	dims := &binding.Dims{
		Vendor:          dev.GetVendor(),
		Name:            dev.GetId(),
		Ports:           make(map[string]*binding.Port),
		HardwareModel:   dev.GetHardwareModel(),
		SoftwareVersion: dev.GetSoftwareVersion(),
		CustomData:      make(map[string]any),
	}
	for _, p := range dev.GetPorts() {
		dims.Ports[p.GetId()] = &binding.Port{
			Name:      p.GetId(),
			Speed:     p.GetSpeed(),
			CardModel: p.GetCardModel(),
			PMD:       p.GetPmd(),
		}
	}
	return &deviceResolution{
		dims: dims,
	}, nil
}

func (b *StcBind) WithReservation(res *binding.Reservation) *StcBind {
	testbed.SetReservationForTesting(res)
	return b
}

// Reserve delegates to b.ReserveFn.
func (b *StcBind) Reserve(ctx context.Context, tb *opb.Testbed, runTime, waitTime time.Duration, partial map[string]string) (*binding.Reservation, error) {
	res := &binding.Reservation{
		ID:   uuid.New(),
		DUTs: make(map[string]binding.DUT),
		ATEs: make(map[string]binding.ATE),
	}
	for _, dut := range tb.Duts {
		resDUT, err := b.resolveDUT(dut)
		if err != nil {
			return nil, err
		}
		res.DUTs[dut.GetId()] = *resDUT
	}
	for _, ate := range tb.Ates {
		resATE, err := b.resolveATE(ate)
		if err != nil {
			return nil, err
		}
		res.ATEs[ate.GetId()] = *resATE
	}

	return res, nil
}

// Release delegates to b.ReleaseFN.
func (b *StcBind) Release(ctx context.Context) error {
	return fmt.Errorf("Release to be implemented.........")
}

// FetchReservation delegates to b.FetchReservationFn.
func (b *StcBind) FetchReservation(ctx context.Context, id string) (*binding.Reservation, error) {
	return nil, fmt.Errorf("FetchReservation to be implemented.........")
}

var _ binding.ATE = (*ATE)(nil)

// ATE is a implementation of binding.ATE comprised of stubs.

// ServiceATE is an ATE that contains a service map.
type ServiceATE struct {
	*binding.AbstractATE
}
type ATE struct {
	*binding.AbstractATE
	DialIxNetworkFn func(context.Context) (*binding.IxNetwork, error)
	DialGNMIFn      func(context.Context, ...grpc.DialOption) (gpb.GNMIClient, error)
	DialOTGFn       func(context.Context, ...grpc.DialOption) (gosnappi.GosnappiApi, error)
}

// DialIxNetwork delegates to a.DialIxNetworkFn.
func (a *ATE) DialIxNetwork(ctx context.Context) (*binding.IxNetwork, error) {
	if a.DialIxNetworkFn == nil {
		log.Fatal("stcbind DialIxNetwork called but DialIxNetworkFn not set")
	}
	return a.DialIxNetworkFn(ctx)
}

// DialGNMI delegates to a.DialGNMIFn.
func (a *ATE) DialGNMI(ctx context.Context, opts ...grpc.DialOption) (gpb.GNMIClient, error) {
	if a.DialGNMIFn == nil {
		log.Fatal("stcbind DialGNMI called but DialGNMIFn not set")
	}
	return a.DialGNMIFn(ctx, opts...)
}

// DialOTG delegates to a.DialOTGFn.
func (a *ATE) DialOTG(ctx context.Context, opts ...grpc.DialOption) (gosnappi.GosnappiApi, error) {
	if a.DialOTGFn == nil {
		log.Fatal("stcbind DialOTG called but DialOTGFn not set")
	}
	return a.DialOTGFn(ctx, opts...)
}
