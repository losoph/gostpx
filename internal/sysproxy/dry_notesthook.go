//go:build !gostpxtest

package sysproxy

func dryFile() string {
	return ""
}

func drySet(path, httpAddr, socksAddr string) error {
	return nil
}

func takeSnapshotDry(path string) (*Snapshot, error) {
	return nil, nil
}

func dryUnset(path string, snap *Snapshot, httpListen, socksListen string) error {
	return nil
}

func dryCurrent(path string) (*Status, error) {
	return nil, nil
}
