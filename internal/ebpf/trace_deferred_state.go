package ebpf

import "time"

// deferredResultPending pre-fills a deferred request's result: the trace
// program stores its result (0 or -errno, never 1) before it sets state 2
// with plain stores, and a weakly ordered CPU may expose the state
// store first. Mirrors TRACE_DEFERRED_PENDING in wafio_trace.c.
const deferredResultPending int32 = 1

// deferredClaimGrace: a claim (state 1) is completed within one program run
// (microseconds). One still standing this long after the request expired was
// abandoned — a program that claimed a hash element the agent had just
// deleted and reused for this request, then found it was not its own.
const deferredClaimGrace = uint64(time.Second)

// deferredRequestDone reports whether the agent may read a deferred
// request's outcome: completed (state 2) with its result visible, never
// claimed (state 0) by its expiry, or claimed and abandoned (state 1) a grace
// period after expiry. Anything else is read again on the next poll.
func deferredRequestDone(state uint64, result int32, expiresNs, now uint64) bool {
	switch state {
	case 2:
		return result != deferredResultPending
	case 1:
		return now >= expiresNs+deferredClaimGrace
	case 0:
		return now >= expiresNs
	}
	return false
}
