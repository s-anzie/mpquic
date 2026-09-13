package http3

import (
	"context"
	"net"
	"sort"
	"time"

	"github.com/quic-go/quic-go"
)

// localPathAddresses reports addresses on interfaces that are currently up.
// Link-local IPv6 needs interface-scoped routing and is intentionally excluded.
func localPathAddresses() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []net.IP
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil {
				result = append(result, ip)
			}
		}
	}
	return result, nil
}

func eligiblePathAddresses(addresses []net.IP, primary, remote net.IP) []net.IP {
	unique := make(map[string]net.IP)
	for _, ip := range addresses {
		if ip == nil || ip.Equal(primary) || ip.IsLoopback() != remote.IsLoopback() ||
			(ip.To4() == nil) != (remote.To4() == nil) ||
			(!ip.IsGlobalUnicast() && !ip.IsLoopback()) {
			continue
		}
		unique[ip.String()] = ip
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]net.IP, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result
}

type discoveredPath struct {
	path      *quic.Path
	transport *quic.Transport
	socket    *net.UDPConn
}

func (p *discoveredPath) close() {
	_ = p.path.Close()
	_ = p.transport.Close()
	_ = p.socket.Close()
}

func (t *Transport) startPathDiscovery(conn *quic.Conn) {
	addresses := t.pathAddresses
	if addresses == nil {
		addresses = localPathAddresses
	}
	t.pathDiscoveryWG.Add(1)
	go func() {
		defer t.pathDiscoveryWG.Done()
		ctx, cancel := context.WithCancel(t.pathDiscoveryCtx)
		stop := context.AfterFunc(conn.Context(), cancel)
		defer stop()
		defer cancel()
		select {
		case <-conn.HandshakeComplete():
		case <-ctx.Done():
			return
		}
		state := conn.ConnectionState()
		if !state.SupportsMultipath.Local || !state.SupportsMultipath.Remote {
			return
		}
		remote, ok := conn.RemoteAddr().(*net.UDPAddr)
		if !ok {
			return
		}
		// UDP connect queries the route's source address without sending data.
		route, err := net.DialUDP("udp", nil, remote)
		if err != nil {
			return
		}
		primary := route.LocalAddr().(*net.UDPAddr).IP
		_ = route.Close()
		paths := make(map[string]*discoveredPath)
		attempted := make(map[string]bool)
		defer func() {
			for _, p := range paths {
				p.close()
			}
		}()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			ips, err := addresses()
			if err == nil {
				candidates := eligiblePathAddresses(ips, primary, remote.IP)
				present := make(map[string]bool, len(candidates))
				for _, ip := range candidates {
					present[ip.String()] = true
				}
				for key, p := range paths {
					if !present[key] {
						p.close()
						delete(paths, key)
					}
				}
				for key := range attempted {
					if !present[key] {
						delete(attempted, key)
					}
				}
				for _, ip := range candidates {
					key := ip.String()
					if attempted[key] || len(paths) >= 4 {
						continue
					}
					socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
					if err != nil {
						continue
					}
					tr := &quic.Transport{Conn: socket}
					path, err := conn.AddPath(tr)
					if err != nil {
						_ = tr.Close()
						_ = socket.Close()
						break // Peer path limits may change on a later scan.
					}
					attempted[key] = true
					p := &discoveredPath{path: path, transport: tr, socket: socket}
					probeCtx, cancelProbe := context.WithTimeout(ctx, 2*time.Second)
					err = path.Probe(probeCtx)
					cancelProbe()
					if err != nil {
						p.close()
						continue
					}
					paths[key] = p
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
