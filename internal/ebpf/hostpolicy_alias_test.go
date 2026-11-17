package ebpf

// Names of shared/hostpolicy that only the tests of this package use. The
// declarations the code uses are in hostpolicy_alias.go.

import "github.com/wafio/wafio-cp-backend/shared/hostpolicy"

const WarnGeoAllowActive = hostpolicy.WarnGeoAllowActive
const WarnGeoAllowNoEscape = hostpolicy.WarnGeoAllowNoEscape
const WarnSSHPortAssumed = hostpolicy.WarnSSHPortAssumed

var ErrAllowlistNestingTooDeep = hostpolicy.ErrAllowlistNestingTooDeep
var ErrAllowlistPortsTooMany = hostpolicy.ErrAllowlistPortsTooMany
var ErrBlocklistNestingTooDeep = hostpolicy.ErrBlocklistNestingTooDeep
var ErrEgressBlockTooBroad = hostpolicy.ErrEgressBlockTooBroad
var ErrGeoRangesExceedCapacity = hostpolicy.ErrGeoRangesExceedCapacity
var ErrIngressDenyNeedsAllow = hostpolicy.ErrIngressDenyNeedsAllow
var ErrIngressDenyNeedsConntrack = hostpolicy.ErrIngressDenyNeedsConntrack
var ErrInvalidPortPolicy = hostpolicy.ErrInvalidPortPolicy
var ErrWildcardBlockNeedsAllowlist = hostpolicy.ErrWildcardBlockNeedsAllowlist
var ErrWildcardBlockNeedsConntrack = hostpolicy.ErrWildcardBlockNeedsConntrack
var matchModifierFields = hostpolicy.MatchModifierFields
var narrowingMatchFields = hostpolicy.NarrowingMatchFields
var LockoutEscape = hostpolicy.LockoutEscape
var MergeGeoPrefixes = hostpolicy.MergeGeoPrefixes
var NeedsDataplaneExemptions = hostpolicy.NeedsDataplaneExemptions
var policyHasNarrowingMatch = hostpolicy.PolicyHasNarrowingMatch
var traceEventIsNoise = hostpolicy.TraceEventIsNoise
var traceOpenKept = hostpolicy.TraceOpenKept
var ValidateFirewallSafety = hostpolicy.ValidateFirewallSafety
var ValidateIPListNesting = hostpolicy.ValidateIPListNesting
