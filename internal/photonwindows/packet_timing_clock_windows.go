//go:build windows && photon_profile

package photonwindows

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fixtureQPC = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
	fixtureQPF = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")
)

// scratch belongs to the window, not a clock call's stack. The window mutex
// serializes its use, avoiding an escaping &local for each sampled clock read.
type fixturePacketTimingClock struct {
	scratch   int64
	frequency uint64
	qpc       uintptr
}

func newFixturePacketTimingClock() (fixturePacketTimingClock, error) {
	if err := fixtureQPC.Find(); err != nil {
		return fixturePacketTimingClock{}, err
	}
	if err := fixtureQPF.Find(); err != nil {
		return fixturePacketTimingClock{}, err
	}
	var c fixturePacketTimingClock
	ok, _, _ := syscall.SyscallN(fixtureQPF.Addr(), uintptr(unsafe.Pointer(&c.scratch)))
	if ok == 0 || c.scratch <= 0 {
		return fixturePacketTimingClock{}, errors.New("fixture packet timing: QPC frequency unavailable")
	}
	c.frequency = uint64(c.scratch)
	c.qpc = fixtureQPC.Addr()
	return c, nil
}

func (*fixturePacketTimingClock) name() string { return "query_performance_counter" }

// The caller holds the window mutex. QPC is shared across producer and owner;
// no durations are formed from a mixture of QPC and time.Now.
func (c *fixturePacketTimingClock) read() (int64, bool) {
	// Direct SyscallN has uintptrkeepalive/noescape semantics. LazyProc.Call's
	// uintptr-escaping variadic wrapper would allocate an argument slice per read.
	ok, _, _ := syscall.SyscallN(c.qpc, uintptr(unsafe.Pointer(&c.scratch)))
	runtime.KeepAlive(c)
	return c.scratch, ok != 0 && c.scratch >= 0
}
