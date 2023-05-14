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

// Package ate controls automated test equipment (ATE) for ONDATRA tests.
package ate

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/openconfig/ondatra/binding"
	"github.com/openconfig/ondatra/internal/rawapis"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	opb "github.com/openconfig/ondatra/proto"
)

var (
	mu   sync.Mutex
	stcs = make(map[binding.ATE]*stcATE)
)

// Topology is an ATE topology.
type Topology struct {
	Interfaces []*opb.InterfaceConfig
	LAGs       []*opb.Lag
}

func stcForATE(ctx context.Context, ate binding.ATE) (*stcATE, error) {
	mu.Lock()
	defer mu.Unlock()
	stc, ok := stcs[ate]
	if !ok {
		ixnet, err := rawapis.FetchStcAgent(ctx, ate)
		if err != nil {
			return nil, err
		}
		stc, err = newStcATE(ctx, ate.Name(), ixnet)
		if err != nil {
			return nil, err
		}
		stcs[ate] = stc
	}
	return stc, nil
}

// PushTopology pushes a topology to an ATE.
func PushTopology(ctx context.Context, ate binding.ATE, top *Topology) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.PushTopology(ctx, top); err != nil {
		return err
	}
	stc.FlushStats()
	return nil
}

// UpdateTopology updates a topology on an ATE.
func UpdateTopology(ctx context.Context, ate binding.ATE, top *Topology, bgpPeerStateOnly bool) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	// TODO(team): Remove this branching once new stc config binding is used.
	if bgpPeerStateOnly {
		err = stc.UpdateBGPPeerStates(ctx, top.Interfaces)
	} else {
		err = stc.UpdateTopology(ctx, top)
	}
	if err != nil {
		return err
	}
	stc.FlushStats()
	return nil
}

// UpdateNetworks updates network groups in a topology on an ATE on the fly.
func UpdateNetworks(ctx context.Context, ate binding.ATE, top *Topology) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	return stc.UpdateNetworkGroups(ctx, top.Interfaces)
}

// StartProtocols starts control plane protocols on an ATE.
func StartProtocols(ctx context.Context, ate binding.ATE) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.StartProtocols(ctx); err != nil {
		return fmt.Errorf("failed to start protocols: %w", err)
	}
	stc.FlushStats()
	return nil
}

// StopProtocols stops control protocols on an ATE.
func StopProtocols(ctx context.Context, ate binding.ATE) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.StopProtocols(ctx); err != nil {
		return err
	}
	stc.FlushStats()
	return nil
}

// StartTraffic starts traffic flows on an ATE.
func StartTraffic(ctx context.Context, ate binding.ATE, flows []*opb.Flow) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.StartTraffic(ctx, flows); err != nil {
		return err
	}
	stc.FlushStats()
	return nil
}

// UpdateTraffic updates traffic flows an an ATE.
func UpdateTraffic(ctx context.Context, ate binding.ATE, flows []*opb.Flow) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.UpdateTraffic(ctx, flows); err != nil {
		return err
	}
	stc.FlushStats()
	return nil
}

// StopTraffic stops traffic flows on an ATE.
func StopTraffic(ctx context.Context, ate binding.ATE) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.StopAllTraffic(ctx); err != nil {
		return err
	}
	stc.FlushStats()
	return nil
}

// FetchGNMI returns the GNMI client for the stc.
func FetchGNMI(ctx context.Context, ate binding.ATE) (gpb.GNMIClient, error) {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return nil, err
	}
	return stc.FetchGNMI(ctx)
}

// SetPortState sets the state of a specified interface on the ATE.
func SetPortState(ctx context.Context, ate binding.ATE, port string, enabled *bool) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	return stc.SetPortState(ctx, port, enabled)
}

// SetLACPState sets the LACP state of a specified interface on the ATE.
func SetLACPState(ctx context.Context, ate binding.ATE, port string, enabled *bool) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	return stc.SetLACPState(ctx, port, enabled)
}

// SendBGPPeerNotification sends a notification from BGP peers.
func SendBGPPeerNotification(ctx context.Context, ate binding.ATE, peerIDs []uint32, code int, subCode int) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.SendBGPPeerNotification(ctx, peerIDs, code, subCode); err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}
	return nil
}

// SendBGPGracefulRestart sends a BGP graceful restart event to BGP peers.
func SendBGPGracefulRestart(ctx context.Context, ate binding.ATE, peerIDs []uint32, delay time.Duration) error {
	stc, err := stcForATE(ctx, ate)
	if err != nil {
		return err
	}
	if err := stc.SendBGPGracefulRestart(ctx, peerIDs, delay); err != nil {
		return fmt.Errorf("failed to send graceful restart: %w", err)
	}
	return nil
}
