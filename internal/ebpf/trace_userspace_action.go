package ebpf

// Userspace policy step of the trace ring reader (trace_manager.go,
// linux-only), kept portable so the decision is testable without a kernel:
// A Simulate verdict never sends a signal.

// userspaceActionEffects are the side effects of a userspace policy verdict.
type userspaceActionEffects struct {
	// kill is the identity-verified signal path (TraceManager.userspaceKill:
	// protected-process guard, pidfd SIGKILL, else a deferred kernel request).
	kill func(evt *TraceEvent, policyID uint32)
	// logf records a Simulate dry run.
	logf func(format string, args ...any)
}

// applyUserspacePolicy evaluates the userspace policies for an event the
// kernel did not already kill and, when their verdict outranks the event's
// action, records it on evt and runs its effect: Kill goes to the signal
// path; Simulate only logs that the process would have been killed — it
// never reaches the signal path. Returns whether a userspace verdict was
// applied.
func applyUserspacePolicy(evt *TraceEvent, pe *PolicyEngine, fx userspaceActionEffects) bool {
	if evt.Action == ActionKill {
		return false // enforced in the kernel already
	}
	action, policyID := pe.Evaluate(*evt)
	if ActionPriority(action) <= ActionPriority(evt.Action) {
		return false
	}
	evt.Action = action
	evt.ActionName = actionName(action)
	evt.PolicyID = policyID
	switch action {
	case ActionKill:
		fx.kill(evt, policyID)
	case ActionSimulate:
		fx.logf("simulate (dry-run) pid=%d policy=%d would have been killed/alerted", evt.PID, policyID)
	}
	return true
}
