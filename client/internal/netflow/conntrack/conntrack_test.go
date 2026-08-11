//go:build linux && !android

package conntrack

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	nfct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	nbnet "github.com/netbirdio/netbird/client/net"
)

type mockListener struct {
	errChan  chan error
	closed   atomic.Bool
	closedCh chan struct{}
}

func newMockListener() *mockListener {
	return &mockListener{
		errChan:  make(chan error, 1),
		closedCh: make(chan struct{}),
	}
}

func (m *mockListener) Listen(evChan chan<- nfct.Event, _ uint8, _ []netfilter.NetlinkGroup) (chan error, error) {
	return m.errChan, nil
}

func (m *mockListener) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.closedCh)
	}
	return nil
}

func TestReconnectAfterError(t *testing.T) {
	first := newMockListener()
	second := newMockListener()
	third := newMockListener()
	listeners := []*mockListener{first, second, third}
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		n := int(callCount.Add(1)) - 1
		return listeners[n], nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Inject an error on the first listener.
	first.errChan <- assert.AnError

	// Wait for reconnect to complete.
	require.Eventually(t, func() bool {
		return callCount.Load() >= 2
	}, 15*time.Second, 100*time.Millisecond, "reconnect should dial a new connection")

	// The first connection must have been closed.
	select {
	case <-first.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection was not closed")
	}

	// Verify the receiver is still running by injecting and handling a second error.
	second.errChan <- assert.AnError

	require.Eventually(t, func() bool {
		return callCount.Load() >= 3
	}, 15*time.Second, 100*time.Millisecond, "second reconnect should succeed")

	ct.Stop()
}

func TestStopDuringReconnectBackoff(t *testing.T) {
	mock := newMockListener()

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		return mock, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Trigger an error so the receiver enters reconnect.
	mock.errChan <- assert.AnError

	// Wait for the error handler to close the old listener before calling Stop.
	select {
	case <-mock.closedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reconnect to start")
	}

	// Stop while reconnecting.
	ct.Stop()

	ct.mux.Lock()
	assert.False(t, ct.started, "started should be false after Stop")
	assert.Nil(t, ct.conn, "conn should be nil after Stop")
	ct.mux.Unlock()
}

func TestStopRaceWithReconnectDial(t *testing.T) {
	first := newMockListener()
	dialStarted := make(chan struct{})
	dialProceed := make(chan struct{})
	second := newMockListener()
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		n := callCount.Add(1)
		if n == 1 {
			return first, nil
		}
		// Second dial: signal that we're in progress, wait for test to call Stop.
		close(dialStarted)
		<-dialProceed
		return second, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Trigger error to enter reconnect.
	first.errChan <- assert.AnError

	// Wait for reconnect's second dial to begin.
	select {
	case <-dialStarted:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for reconnect dial")
	}

	// Stop while dial is in progress (conn is nil at this point).
	ct.Stop()

	// Let the dial complete. reconnect should detect started==false and close the new conn.
	close(dialProceed)

	// The second connection should be closed (not leaked).
	select {
	case <-second.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("second connection was leaked after Stop")
	}

	ct.mux.Lock()
	assert.False(t, ct.started)
	assert.Nil(t, ct.conn)
	ct.mux.Unlock()
}

func TestCloseRaceWithReconnectDial(t *testing.T) {
	first := newMockListener()
	dialStarted := make(chan struct{})
	dialProceed := make(chan struct{})
	second := newMockListener()
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		n := callCount.Add(1)
		if n == 1 {
			return first, nil
		}
		close(dialStarted)
		<-dialProceed
		return second, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	first.errChan <- assert.AnError

	select {
	case <-dialStarted:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for reconnect dial")
	}

	// Close while dial is in progress (conn is nil).
	require.NoError(t, ct.Close())

	close(dialProceed)

	// The second connection should be closed (not leaked).
	select {
	case <-second.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("second connection was leaked after Close")
	}

	ct.mux.Lock()
	assert.False(t, ct.started)
	assert.Nil(t, ct.conn)
	ct.mux.Unlock()
}

func TestStartIsIdempotent(t *testing.T) {
	mock := newMockListener()
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		callCount.Add(1)
		return mock, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Second Start should be a no-op.
	err = ct.Start(false)
	require.NoError(t, err)

	assert.Equal(t, int32(1), callCount.Load(), "dial should only be called once")

	ct.Stop()
}

func TestInferDirectionForFirewallConnectionMarks(t *testing.T) {
	ct := &ConnTrack{}

	assert.Equal(t, nftypes.Ingress, ct.inferDirection(nbnet.PreroutingFwmarkRedirected, netip.Addr{}, netip.Addr{}))
	assert.Equal(t, nftypes.Ingress, ct.inferDirection(nbnet.PreroutingFwmarkMasquerade, netip.Addr{}, netip.Addr{}))
	assert.Equal(t, nftypes.Egress, ct.inferDirection(nbnet.PreroutingFwmarkMasqueradeReturn, netip.Addr{}, netip.Addr{}))
}

// The firewall writes connection marks with OR semantics, so a single connection can
// carry the data plane mark together with a prerouting mark. Direction inference must
// still classify those combinations correctly.
func TestInferDirectionForCombinedConnectionMarks(t *testing.T) {
	ct := &ConnTrack{}

	tests := []struct {
		name     string
		mark     uint32
		expected nftypes.Direction
	}{
		{
			name:     "data plane in combined with redirected",
			mark:     nbnet.DataPlaneMarkIn | nbnet.PreroutingFwmarkRedirected,
			expected: nftypes.Ingress,
		},
		{
			name:     "data plane in combined with masquerade",
			mark:     nbnet.DataPlaneMarkIn | nbnet.PreroutingFwmarkMasquerade,
			expected: nftypes.Ingress,
		},
		{
			name:     "data plane in combined with redirected and masquerade",
			mark:     nbnet.DataPlaneMarkIn | nbnet.PreroutingFwmarkRedirected | nbnet.PreroutingFwmarkMasquerade,
			expected: nftypes.Ingress,
		},
		{
			// DataPlaneMarkOut is a superset of DataPlaneMarkIn's bits, so egress has
			// to be evaluated first for this to resolve correctly.
			name:     "data plane out combined with masquerade return",
			mark:     nbnet.DataPlaneMarkOut | nbnet.PreroutingFwmarkMasqueradeReturn,
			expected: nftypes.Egress,
		},
		{
			name:     "data plane out alone",
			mark:     nbnet.DataPlaneMarkOut,
			expected: nftypes.Egress,
		},
		{
			name:     "data plane in alone",
			mark:     nbnet.DataPlaneMarkIn,
			expected: nftypes.Ingress,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ct.inferDirection(tc.mark, netip.Addr{}, netip.Addr{}),
				"mark %#x should infer %v", tc.mark, tc.expected)
		})
	}
}
