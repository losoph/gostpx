//go:build gostpxtest

package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
)

func dryFile() string {
	return os.Getenv("GOSTPX_SYSPROXY_DRY")
}

func drySet(path, httpAddr, socksAddr string) error {
	httpHost, httpPort, err := parseHostPort(httpAddr)
	if err != nil {
		return fmt.Errorf("invalid httpAddr %q: %w", httpAddr, err)
	}
	socksHost, socksPort, err := parseHostPort(socksAddr)
	if err != nil {
		return fmt.Errorf("invalid socksAddr %q: %w", socksAddr, err)
	}
	st := Status{
		Enabled:   true,
		HTTPHost:  httpHost,
		HTTPPort:  httpPort,
		SOCKSHost: socksHost,
		SOCKSPort: socksPort,
		Service:   "DryService",
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func takeSnapshotDry(path string) (*Snapshot, error) {
	st, err := dryCurrent(path)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Dry: st,
	}, nil
}

func dryUnset(path string, snap *Snapshot, httpListen, socksListen string) error {
	cur, err := dryCurrent(path)
	if err != nil {
		return err
	}

	touchHTTP := httpListen == "" || (cur != nil && cur.Enabled && matchesListenAddr(cur.HTTPHost, cur.HTTPPort, httpListen))
	touchSOCKS := (httpListen == "" && socksListen == "") || (socksListen != "" && cur != nil && cur.Enabled && matchesListenAddr(cur.SOCKSHost, cur.SOCKSPort, socksListen))

	if !touchHTTP && !touchSOCKS {
		return nil
	}

	if cur == nil {
		cur = &Status{Service: "DryService"}
	}

	if snap != nil && snap.Dry != nil {
		if touchHTTP {
			cur.HTTPHost = snap.Dry.HTTPHost
			cur.HTTPPort = snap.Dry.HTTPPort
		}
		if touchSOCKS {
			cur.SOCKSHost = snap.Dry.SOCKSHost
			cur.SOCKSPort = snap.Dry.SOCKSPort
		}
		cur.Enabled = (cur.HTTPHost != "" && cur.HTTPPort != 0) || (cur.SOCKSHost != "" && cur.SOCKSPort != 0)
	} else {
		if touchHTTP {
			cur.HTTPHost = ""
			cur.HTTPPort = 0
		}
		if touchSOCKS {
			cur.SOCKSHost = ""
			cur.SOCKSPort = 0
		}
		cur.Enabled = (cur.HTTPHost != "" && cur.HTTPPort != 0) || (cur.SOCKSHost != "" && cur.SOCKSPort != 0)
	}

	data, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func dryCurrent(path string) (*Status, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Status{
				Enabled: false,
				Service: "DryService",
			}, nil
		}
		return nil, err
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	if st.Service == "" {
		st.Service = "DryService"
	}
	return &st, nil
}
