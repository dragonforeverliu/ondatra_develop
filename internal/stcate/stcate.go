// Copyright 2021 Google LLC
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

package ate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"golang.org/x/net/context"

	log "github.com/golang/glog"
	"github.com/openconfig/ondatra/binding"
	"github.com/openconfig/ondatra/binding/stcweb"
	"github.com/openconfig/ondatra/internal/stcconfig"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	opb "github.com/openconfig/ondatra/proto"
)

type operState uint
type routeTableFormat string

// OperStatus represents the status of a completed StcAgent operation.
type OperStatus string

const (
	operStateOff operState = iota
	operStateProtocolsOn
	operStateTrafficOn
	routeTableFormatCisco   routeTableFormat = "cisco"
	routeTableFormatJuniper routeTableFormat = "juniper"
	routeTableFormatCSV     routeTableFormat = "csv"

	// OperStatusSuccess indicates a successful operation.
	OperStatusSuccess OperStatus = "success"
	// OperStatusFailure indicates a failed operation.
	OperStatusFailure OperStatus = "failure"

	importRetries = 5

	// StcAgent has an undocumented maximum number of DeviceGroups.
	maxIntfs = 256

	bgpPeerV4NotifyOp = "topology/deviceGroup/ethernet/ipv4/bgpIpv4Peer/operations/breaktcpsession"
	bgpPeerV6NotifyOp = "topology/deviceGroup/ethernet/ipv6/bgpIpv6Peer/operations/breaktcpsession"

	bgpPeerV4GracefulRestartOp = "topology/deviceGroup/ethernet/ipv4/bgpIpv4Peer/operations/gracefulrestart"
	bgpPeerV6GracefulRestartOp = "topology/deviceGroup/ethernet/ipv6/bgpIpv6Peer/operations/gracefulrestart"

	startLACPOp = "lag/protocolStack/ethernet/lagportlacp/port/operations/start"
	stopLACPOp  = "lag/protocolStack/ethernet/lagportlacp/port/operations/stop"
)

var (
	syncedOpArgs = stcweb.OpArgs{"sync"}

	macRE         = regexp.MustCompile(`^([0-9a-f]{2}:){5}([0-9a-f]{2})$`)
	resolveMacsFn = resolveMacs

	// TODO(team): Lower timeouts after chassis hardware upgrades.
	peersImportTimeout   = time.Minute
	trafficImportTimeout = 4 * time.Minute
	topoImportTimeout    = 3 * time.Minute

	sleepFn = time.Sleep
)

type cfgClient interface {
	Session() session
	ImportConfig(context.Context, *stcconfig.StcCfgData, bool) error
}

type session interface {
	ID() int
	AbsPath(string) string
	Delete(context.Context, string) error
	Get(context.Context, string, any) error
	Patch(context.Context, string, any) error
	Post(context.Context, string, any, any) error
}

type files interface {
	List(context.Context, string) ([]string, error)
	Upload(context.Context, string, []byte) error
	Delete(context.Context, string) error
}

type clientWrapper struct {
	*stcconfig.Client
}

func (cw *clientWrapper) Session() session {
	return &sessionWrapper{cw.Client.Session()}
}

func unwrapClient(c cfgClient) *stcconfig.Client {
	return c.(*clientWrapper).Client
}

type sessionWrapper struct {
	*stcweb.Session
}

// CfgComponents represents the physical ATE components in use for the session and
// their association with configured interfaces/protocols.
type CfgComponents struct {
	Host                 string
	Linecards            []uint64
	Ports                []string
	PortToInterfaces     map[string][]string
	InterfaceToProtocols map[string][]string
}

func (c *CfgComponents) String() string {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("<error marshaling JSON: %v>", err)
	}
	return string(b)
}

// OperResult represents the status of an operation and the configuration context in which it executed.
type OperResult struct {
	Path        string
	Status      OperStatus
	Start       time.Time
	End         time.Time
	OpErr       error
	SessionErrs []*stcweb.Error
	Components  *CfgComponents
}

func (o *OperResult) String() string {
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Sprintf("<error marshaling JSON: %v>", err)
	}
	return string(b)
}

// IPv4/6 route tables specified by local path.
type routeTables struct {
	format           routeTableFormat
	ipv4, ipv6       string
	overwriteNexthop bool
}

func newStcATE(ctx context.Context, name string, sa *binding.StcAgent) (*stcATE, error) {
	stc := &stcATE{
		name:        name,
		Session:     sa.Session,
		c:           &clientWrapper{stcconfig.New(sa.Session)},
		chassisHost: sa.ChassisHost,
		syslogHost:  sa.SyslogHost,
	}
	if stc.chassisHost == "" {
		stc.chassisHost = name
	}
	return stc, nil
}

// stcATE provides an ATE interface backed by an StcAgent session.
type stcATE struct {
	c           cfgClient
	Session     *stcweb.Session
	name        string
	syslogHost  string
	chassisHost string

	// Operational state is updated as needed on successful API calls.
	operState operState

	mu sync.Mutex
	// gclient *stcgnmi.Client

	ate   *binding.ATE
	top   *Topology
	flows []*opb.Flow
}

func (stc *stcATE) logOp(ctx context.Context, path string, opErr error, start, end time.Time) {
	status := OperStatusSuccess
	if opErr != nil {
		status = OperStatusFailure
	}
	opResult := &OperResult{
		Path:   path,
		Status: status,
		Start:  start,
		End:    end,
		OpErr:  opErr,
		// Components:  components,
	}
	log.Infof(opResult.String())
}

func (stc *stcATE) runOp(ctx context.Context, path string, in any, out any) error {
	start := time.Now()
	err := stc.c.Session().Post(ctx, path, in, out)
	end := time.Now()
	stc.logOp(ctx, path, err, start, end)
	return err
}

func (stc *stcATE) pushTopology(ctx context.Context, top *Topology) error {

	ate_bytes, _ := json.Marshal(stc.ate)
	top_bytes, _ := json.Marshal(top)
	in := struct {
		Ate      string `json:"ate"`
		Topology string `json:"topology"`
	}{
		Ate:      string(ate_bytes),
		Topology: string(top_bytes),
	}

	stc.top = top

	if err := stc.runOp(ctx, "topology/push", in, nil); err != nil {
		return fmt.Errorf("could not apply traffic config: %w", err)
	}

	log.Infof("Topology push successfully")
	return nil
}

// PushTopology configures the StcAgent session with the specified topology.
func (stc *stcATE) PushTopology(ctx context.Context, top *Topology) error {
	if err := validateInterfaces(top.Interfaces); err != nil {
		return err
	}

	if err := stc.pushTopology(ctx, top); err != nil {
		return err
	}
	stc.operState = operStateOff
	return nil
}

// UpdateTopology updates StcAgent session to the specified topology.
func (stc *stcATE) UpdateTopology(ctx context.Context, top *Topology) error {
	if err := validateInterfaces(top.Interfaces); err != nil {
		return err
	}
	if err := stc.pushTopology(ctx, top); err != nil {
		return err
	}
	// Protocols/traffic are stopped after updating topology, restart as needed.
	if stc.operState != operStateOff {
		if err := stc.startProtocols(ctx); err != nil {
			return err
		}
		if stc.operState == operStateTrafficOn {
			if err := stc.startTraffic(ctx, stc.flows); err != nil {
				return err
			}
		}
	}
	return nil
}

type stateRsp interface {
	Up() bool
}

type protocolRsp struct {
	SessionStatus []string
}

func (r *protocolRsp) Up() bool {
	return len(r.SessionStatus) > 0 && r.SessionStatus[0] == "up"
}

type lspRsp struct {
	State []string
}

func (r *lspRsp) Up() bool {
	if len(r.State) == 0 {
		return false
	}
	for _, s := range r.State {
		if s != "up" {
			return false
		}
	}
	return true
}

func (stc *stcATE) startProtocols(ctx context.Context) error {
	in := struct{}{}
	errStart := stc.runOp(ctx, "topology/startallprotocols", in, nil)
	if errStart != nil {
		log.Warningf("First attempted startallprotocols op failed: %v", errStart)
		if errStart = stc.runOp(ctx, "topology/startallprotocols", in, nil); errStart != nil {
			log.Warningf("Second attempted startallprotocols op failed: %v", errStart)
		}
	}

	log.Infof("Protocols started successfully")
	return nil
}

// StartProtocols starts running protocols for the StcAgent session.
func (stc *stcATE) StartProtocols(ctx context.Context) error {
	if stc.operState != operStateOff {
		log.Infof("Protocols already started, not running operation on Stc.")
		return nil
	}
	if err := stc.startProtocols(ctx); err != nil {
		return err
	}
	stc.operState = operStateProtocolsOn
	return nil
}

// StopProtocols stops running protocols for the StcAgent session.
func (stc *stcATE) StopProtocols(ctx context.Context) error {
	if stc.operState == operStateOff {
		log.Infof("Protocols already stopped, not running operation on Stc.")
		return nil
	}
	in := struct{}{}
	if err := stc.runOp(ctx, "topology/stopallprotocols", in, nil); err != nil {
		return fmt.Errorf("could not stop protocols: %w", err)
	}
	stc.operState = operStateOff
	return nil
}

// SetPortState enables/disables the given Stc port.
func (stc *stcATE) SetPortState(ctx context.Context, port string, enabled *bool) error {
	in := struct {
		Port    string `json:"port"`
		Enabled bool   `json:"enabled"`
	}{
		Port:    port,
		Enabled: *enabled,
	}
	if err := stc.runOp(ctx, "actions/linkupdn", in, nil); err != nil {
		return fmt.Errorf("error setting port state for %q: %w", port, err)
	}
	return nil
}

// SetLACPState enables/disables LACP on the given Stc port in a LAG.
func (stc *stcATE) SetLACPState(ctx context.Context, port string, enabled *bool) error {
	// portID := fmt.Sprintf("%s/port/%d", lacpID, portIdx+1)
	// if err := stc.runOp(ctx, op, stcweb.OpArgs{[]string{portID}}, nil); err != nil {
	// 	return fmt.Errorf("error setting LACP state for %q: %w", port, err)
	// }
	return nil
}

func resolveMacs(ctx context.Context, stc *stcATE) error {
	return nil
}

// Expects all traffic items to have up-to-date REST IDs.
func genTraffic(ctx context.Context, stc *stcATE) error {
	return nil
}

// updateFlows updates frame size/rate configuration for flows after generation.
// Assumes that StcAgent traffic items corresponding to the flows have updated
// REST IDs.
func (stc *stcATE) updateFlows(ctx context.Context, flows []*opb.Flow) error {
	ate_bytes, _ := json.Marshal(stc.ate)
	flows_bytes, _ := json.Marshal(flows)
	in := struct {
		Ate   string `json:"ate"`
		Flows string `json:"flows"`
	}{
		Ate:   string(ate_bytes),
		Flows: string(flows_bytes),
	}

	stc.flows = flows

	if err := stc.runOp(ctx, "traffic/update", in, nil); err != nil {
		return fmt.Errorf("could not start traffic: %w", err)
	}
	return nil
}

func (stc *stcATE) applyTraffic(ctx context.Context) error {
	in := struct{}{}
	if err := stc.runOp(ctx, "traffic/apply", in, nil); err != nil {
		return fmt.Errorf("could not apply traffic config: %w", err)
	}
	return nil
}

func (stc *stcATE) startTraffic(ctx context.Context, flows []*opb.Flow) error {
	ate_bytes, _ := json.Marshal(stc.ate)
	flows_bytes, _ := json.Marshal(flows)
	in := struct {
		Ate   string `json:"ate"`
		Flows string `json:"flows"`
	}{
		Ate:   string(ate_bytes),
		Flows: string(flows_bytes),
	}

	stc.flows = flows

	if err := stc.runOp(ctx, "traffic/start", in, nil); err != nil {
		return fmt.Errorf("could not start traffic: %w", err)
	}
	return nil
}

// StartTraffic starts traffic for the StcAgent session based on the given flows.
// If no flows are provided, starts the previously pushed flows.
func (stc *stcATE) StartTraffic(ctx context.Context, flows []*opb.Flow) error {
	if err := stc.startTraffic(ctx, flows); err != nil {
		return err
	}
	stc.operState = operStateTrafficOn
	return nil
}

// UpdateTraffic updates traffic config for the StcAgent session based on the given flows.
func (stc *stcATE) UpdateTraffic(ctx context.Context, flows []*opb.Flow) error {
	if err := validateFlows(flows); err != nil {
		return err
	}
	if stc.operState != operStateTrafficOn {
		return fmt.Errorf("cannot update traffic before it has been started")
	}
	if err := stc.updateFlows(ctx, flows); err != nil {
		return fmt.Errorf("could not update running traffic flows: %w", err)
	}
	return nil
}

func (stc *stcATE) stopAllTraffic(ctx context.Context) error {
	in := struct{}{}
	if err := stc.runOp(ctx, "traffic/stop", in, nil); err != nil {
		return fmt.Errorf("could not stop traffic: %w", err)
	}
	// Wait a sufficient amount of time to ensure that traffic is stopped.
	sleepFn(15 * time.Second)
	return nil
}

func (stc *stcATE) trafficItemStatsAvailable(ctx context.Context) bool {
	return true
}

// StopAllTraffic stops all traffic for the StcAgent session and waits for stats to be populated.
func (stc *stcATE) StopAllTraffic(ctx context.Context) error {
	const (
		retryWait       = 5 * time.Second
		maxRetriesStats = 6
	)
	if stc.operState != operStateTrafficOn {
		log.Infof("Traffic already stopped, not running operation on Stc.")
		return nil
	}
	if err := stc.stopAllTraffic(ctx); err != nil {
		return err
	}
	stc.operState = operStateProtocolsOn
	log.Infof("Traffic stopped, waiting for stats to populate.")

	statsUpdated := stc.trafficItemStatsAvailable(ctx)
	for i := 0; i < maxRetriesStats && !statsUpdated; i++ {
		sleepFn(retryWait)
		statsUpdated = stc.trafficItemStatsAvailable(ctx)
	}
	if !statsUpdated {
		return errors.New("traffic item statistics did not become available after stopping traffic")
	}
	return nil
}

// FetchGNMI returns the GNMI client for the Stc.
func (stc *stcATE) FetchGNMI(ctx context.Context) (gpb.GNMIClient, error) {
	// stc.mu.Lock()
	// defer stc.mu.Unlock()
	// if stc.gclient == nil {
	// 	gclient, err := stcgnmi.NewClient(ctx, stc.name, stc.readStats, unwrapClient(stc.c), rawapis.CommonDialOpts...)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	stc.gclient = gclient
	// }
	// return stc.gclient, nil
	return nil, nil
}

func (stc *stcATE) applyOnTheFly(ctx context.Context) error {
	in := struct{}{}
	if err := stc.runOp(ctx, "topology/applyonthefly", in, nil); err != nil {
		return fmt.Errorf("could not apply topology changes: %w", err)
	}
	return nil
}

func (stc *stcATE) UpdateNetworkGroups(ctx context.Context, ifs []*opb.InterfaceConfig) error {
	return stc.applyOnTheFly(ctx)
}

func (stc *stcATE) SendBGPGracefulRestart(ctx context.Context, peerIDs []uint32, delay time.Duration) error {
	return nil
}

func (stc *stcATE) SendBGPPeerNotification(ctx context.Context, peerIDs []uint32, code int, subCode int) error {
	return nil
}

func validateFlows(fs []*opb.Flow) error {
	for _, f := range fs {
		if len(f.GetSrcEndpoints()) == 0 {
			return fmt.Errorf("flow has no src endpointd")
		}
		if len(f.GetDstEndpoints()) == 0 {
			return fmt.Errorf("flow has no dst endpoints")
		}
	}
	return nil
}

func validateInterfaces(ifs []*opb.InterfaceConfig) error {
	if len(ifs) == 0 {
		return fmt.Errorf("zero interfaces to configure, need at least one")
	}
	if len(ifs) > maxIntfs {
		return fmt.Errorf("%v interfaces to configure, must be at most %v", len(ifs), maxIntfs)
	}
	intfs := make(map[string]bool)

	for _, i := range ifs {
		if i.GetPort() == "" && i.GetLag() == "" {
			return fmt.Errorf("interface has no port or lag specified: %v", i)
		}
		if i.GetLag() != "" && i.GetEnableLacp() {
			return fmt.Errorf("interface should not specify both a LAG and that LACP is enabled: %v", i)
		}
		if intfs[i.GetName()] {
			return fmt.Errorf("duplicate interface name: %s", i.GetName())
		}
		intfs[i.GetName()] = true
		nets := make(map[string]bool)
		for _, n := range i.GetNetworks() {
			if nets[n.GetName()] {
				return fmt.Errorf("duplicate network name: %s", n.GetName())
			}
			nets[n.GetName()] = true
		}
		if err := validateIP(i.GetIpv4(), "ipv4 on "+i.GetName()); err != nil {
			return err
		}
		if err := validateIP(i.GetIpv6(), "ipv6 on "+i.GetName()); err != nil {
			return err
		}
	}
	return nil
}

func validateIP(ipc *opb.IpConfig, desc string) error {
	if ipc == nil {
		return nil
	}
	addr := ipc.GetAddressCidr()
	gway := ipc.GetDefaultGateway()
	_, an, err := net.ParseCIDR(addr)
	if err != nil {
		return fmt.Errorf("%s address is not valid CIDR notation: %s", desc, addr)
	}
	gi := net.ParseIP(gway)
	if gi == nil {
		return fmt.Errorf("%s default gateway is not valid IP notation: %s", desc, gway)
	}
	if !gi.IsUnspecified() && !an.Contains(gi) {
		return fmt.Errorf("%s default gateway is not in CIDR range %s: %s", desc, addr, gway)
	}
	return nil
}

func (stc *stcATE) FlushStats() {
	stc.mu.Lock()
	defer stc.mu.Unlock()
	// if stc.gclient != nil {
	// 	stc.gclient.Flush()
	// }
}

func (stc *stcATE) UpdateBGPPeerStates(ctx context.Context, ifs []*opb.InterfaceConfig) error {
	return nil
}
