package cacert

import "context"

type CACertClient struct{}

func (CACertClient) IssueUserCert(ctx context.Context, pubKey []byte, principals []string, durationSec uint64) ([]byte, error) {
	return nil, nil
}

func (CACertClient) IssueHostCert(ctx context.Context, pubKey []byte, principals []string, durationSec uint64) ([]byte, error) {
	return nil, nil
}
