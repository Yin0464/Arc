package dns

import "context"

type dohFunc func(ctx context.Context, q []byte, remote bool) ([]byte, error)

func (f dohFunc) Race(ctx context.Context, q []byte, remote bool) ([]byte, error) {
	return f(ctx, q, remote)
}

func (dohFunc) CloseRemote() {}
