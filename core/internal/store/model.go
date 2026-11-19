package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
)

type Protocol uint8

const (
	ProtoAnyTLS Protocol = 1
	ProtoTrojan Protocol = 2
)

// MaxEndpoints bounds Catalog.Endpoints; Node.EpID is a uint8.
const MaxEndpoints = 256

// SchemaVersion is the node-table JSON layout written by cmd/codegen.
const SchemaVersion = 3

// KeyLen is the stored key size per protocol: AnyTLS sends SHA-256(password),
// Trojan sends hex(SHA-224(password)).
var KeyLen = [...]int{ProtoAnyTLS: 32, ProtoTrojan: 56}

// UpstreamProfile is what every node of one protocol shares: the DoH servers
// that resolve its endpoints and the derived password key.
type UpstreamProfile struct {
	Proto   Protocol `json:"proto"`
	DoHUrls []string `json:"doh"`
	Key     []byte   `json:"key"`
}

type Region struct {
	Name  string     `json:"name"`
	SNI   string     `json:"sni,omitempty"`
	Opts  []NodeOpts `json:"opts"`
	Nodes []Node     `json:"nodes"`
}

type NodeOpts struct {
	Fingerprint                 string   `json:"fingerprint,omitempty"`
	ALPN                        []string `json:"alpn,omitempty"`
	SkipCertVerify              bool     `json:"skip_cert_verify,omitempty"`
	UDP                         bool     `json:"udp,omitempty"`
	IdleSessionCheckIntervalSec int      `json:"idle_check_sec,omitempty"`
	IdleSessionTimeoutSec       int      `json:"idle_timeout_sec,omitempty"`
	MinIdleSession              int      `json:"min_idle,omitempty"`
	MinIdleSessionSet           bool     `json:"min_idle_set,omitempty"`
	PaddingScheme               string   `json:"padding,omitempty"`
	ClientMetadata              string   `json:"metadata,omitempty"`
}

type Node struct {
	Name  string   `json:"name"`
	SNI   string   `json:"sni,omitempty"`
	Port  uint16   `json:"port"`
	EpID  uint8    `json:"ep"`
	Proto Protocol `json:"proto"`
	Opt   uint8    `json:"opt,omitempty"`
}

// Catalog is the node table. The app loads plaintext JSON at runtime and hands
// it to the core through Load, so node changes never need a rebuild of the engine.
type Catalog struct {
	Version          int               `json:"version"`
	Generated        int64             `json:"generated,omitempty"`
	StaticDoHIP      map[string]string `json:"static_doh_ip,omitempty"`
	StaticEndpointIP map[string]string `json:"static_endpoint_ip,omitempty"`
	Endpoints        []string          `json:"endpoints"`
	Profiles         []UpstreamProfile `json:"profiles"`
	Regions          []Region          `json:"regions"`

	byProto [len(KeyLen)]*UpstreamProfile
}

var (
	empty   = &Catalog{}
	current atomic.Pointer[Catalog]
)

// Get returns the active catalog; it is empty until Load succeeds. A loaded
// catalog is immutable, so callers may keep pointers into it.
func Get() *Catalog {
	if c := current.Load(); c != nil {
		return c
	}
	return empty
}

// Loaded reports whether a catalog has been installed.
func Loaded() bool { return current.Load() != nil }

// Parse decodes and validates one node-table JSON document.
func Parse(b []byte) (*Catalog, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	c := &Catalog{}
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	// Runtime resolves DoH and endpoints live; baked IPs are ignored.
	c.StaticDoHIP = nil
	c.StaticEndpointIP = nil
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Load parses b and makes it the active catalog.
func Load(b []byte) error {
	c, err := Parse(b)
	if err != nil {
		return err
	}
	current.Store(c)
	return nil
}

// Encode is the inverse of Parse.
func (c *Catalog) Encode() ([]byte, error) { return json.Marshal(c) }

func (c *Catalog) validate() error {
	if c.Version != SchemaVersion {
		return fmt.Errorf("store: schema version %d, want %d", c.Version, SchemaVersion)
	}
	if len(c.Endpoints) == 0 || len(c.Endpoints) > MaxEndpoints {
		return fmt.Errorf("store: %d endpoints", len(c.Endpoints))
	}
	c.byProto = [len(KeyLen)]*UpstreamProfile{}
	for i := range c.Profiles {
		p := &c.Profiles[i]
		switch {
		case p.Proto != ProtoAnyTLS && p.Proto != ProtoTrojan:
			return fmt.Errorf("store: profile %d: bad protocol", i)
		case c.byProto[p.Proto] != nil:
			return fmt.Errorf("store: protocol %d has two profiles", p.Proto)
		case len(p.DoHUrls) == 0:
			return fmt.Errorf("store: protocol %d has no DoH", p.Proto)
		case len(p.Key) != KeyLen[p.Proto] || keyEmpty(p.Key):
			return fmt.Errorf("store: protocol %d key must be %d non-zero bytes", p.Proto, KeyLen[p.Proto])
		}
		c.byProto[p.Proto] = p
	}
	if len(c.Profiles) == 0 {
		return errors.New("store: no profiles")
	}
	if len(c.Regions) == 0 {
		return errors.New("store: no regions")
	}
	for i := range c.Regions {
		r := &c.Regions[i]
		if r.Name == "" || len(r.Nodes) == 0 {
			return fmt.Errorf("store: region %d is empty", i)
		}
		for k := range r.Nodes {
			n := &r.Nodes[k]
			switch {
			case n.Name == "":
				return fmt.Errorf("store: %s node %d has no name", r.Name, k)
			case n.Proto != ProtoAnyTLS && n.Proto != ProtoTrojan:
				return fmt.Errorf("store: %s: bad protocol", n.Name)
			case c.byProto[n.Proto] == nil:
				return fmt.Errorf("store: %s: no profile for its protocol", n.Name)
			case n.Port == 0 || int(n.EpID) >= len(c.Endpoints) || int(n.Opt) >= len(r.Opts):
				return fmt.Errorf("store: %s: bad port/endpoint/opts", n.Name)
			case r.NodeSNI(n) == "":
				return fmt.Errorf("store: %s: empty SNI", n.Name)
			}
		}
	}
	return nil
}

func keyEmpty(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

var noProfile = &UpstreamProfile{}

// Profile returns the shared settings for protocol p. A validated catalog has
// one for every protocol its nodes use; others get an empty profile.
func (c *Catalog) Profile(p Protocol) *UpstreamProfile {
	if p != ProtoAnyTLS && p != ProtoTrojan {
		panic("store: bad protocol")
	}
	if pr := c.byProto[p]; pr != nil {
		return pr
	}
	return noProfile
}

func (r *Region) NodeSNI(n *Node) string {
	if n.SNI == "" {
		return r.SNI
	}
	return n.SNI
}

func (r *Region) NodeOpts(n *Node) *NodeOpts { return &r.Opts[n.Opt] }

func (n *Node) ProtoLabel() string {
	return [...]string{"", "AnyTLS", "Trojan"}[n.Proto]
}

type uiNode struct {
	Name  string `json:"name"`
	Proto string `json:"proto"`
}

type uiRegion struct {
	Name  string   `json:"name"`
	Nodes []uiNode `json:"nodes"`
}

// UIJSON is the catalog view the app renders: regions in order, each with its
// nodes' display name and protocol label. Indices match SwitchActive.
func (c *Catalog) UIJSON() []byte {
	out := make([]uiRegion, len(c.Regions))
	for i := range c.Regions {
		r := &c.Regions[i]
		out[i] = uiRegion{Name: r.Name, Nodes: make([]uiNode, len(r.Nodes))}
		for k := range r.Nodes {
			out[i].Nodes[k] = uiNode{Name: r.Nodes[k].Name, Proto: r.Nodes[k].ProtoLabel()}
		}
	}
	b, _ := json.Marshal(out)
	return b
}
