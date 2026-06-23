package policy

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ZeeshanDarasa/chainsaw-core/tenancy"
)

// demoPolicyPrefix marks every policy seeded by DemoPolicies(). Used
// by IsDemoPolicy so activation telemetry can distinguish a "first
// blocked install on a seeded demo rule" from a normal block.
const demoPolicyPrefix = "Demo: "

// MalwareFeedPolicyName is the policy_name surfaced on every malware-feed
// refusal (CHW-2303). The proxy's malware-block path emits this name when no
// operator-defined policy was the proximate cause — the block originates from
// the malicious-packages feed, not a configured rule, but the wire response
// still needs a `policy_name` so the developer-side error output names both the
// signal (MAL-NNNN id) AND a human-readable policy label.
//
// This is a PRODUCTION label: it shows to every customer on every malware-feed
// block — including orgs that never had, or have since deleted, the Try-Me
// rule below. It therefore deliberately does NOT carry demoPolicyPrefix. A
// feed-driven refusal is not a demo rule, and labelling a real malware block
// "Demo: ..." read as unpolished/untrustworthy. Activation telemetry does not
// key off this name: the malware-feed path tags its first-block event with
// block_source="malware_feed" (see server_repo_pipeline.go), so the label and
// the telemetry classification are decoupled. The demo-seeded rule keeps its
// "Demo: " prefix because it genuinely is an editable Try-Me rule.
//
// Chain305.com smoke 2026-05-20 confirmed npm-tarball refusals were shipping no
// `policy_name` at all, breaking parity with the pip path (where the policy
// engine drove the block). Wire this constant through every malware-feed-side
// refusal builder so both ecosystems read the same shape.
const MalwareFeedPolicyName = "Block known malware"

// DemoPolicies is the canonical set of demo policies seeded once per
// new org so a brand-new user can run a single install against a
// known-malicious or typosquat package and feel Chainsaw block it —
// the activation moment that turns "I signed up" into "I get it".
//
// Unlike SystemPolicies, demo policies are fully editable AND
// deletable. They go through the regular per-org seed path
// (SeedPoliciesIfNeededTx), which dedups by name, so re-runs against
// the same org are no-ops and an operator who deletes a demo policy
// stays deleted across restarts.
//
// Two policies (one condition each) instead of one policy with two
// conditions: Conditions are AND-composed, so a single policy with
// both flags set would only fire on packages that are simultaneously
// known-malicious AND a typosquat — almost nothing. Two policies give
// OR semantics naturally.
func DemoPolicies() []Policy {
	isMaliciousTrue := true
	isTyposquatTrue := true
	return []Policy{
		{
			Name:        demoPolicyPrefix + "Block known malware",
			Description: "Demo policy seeded on org creation. Blocks any package flagged in the OpenSSF malicious-packages feed (and the Docker malware feed for OCI). Try it: install a known-malicious package from the QUICKSTART_FIRST_BLOCK guide. Edit or delete this rule once you've seen it fire.",
			Mode:        ModeBlock,
			Status:      StatusEnabled,
			Conditions: Conditions{
				IsKnownMalicious: &isMaliciousTrue,
			},
			Identifier: Identifier{
				TargetPackageRepo:    "*",
				TargetPackageName:    "*",
				TargetPackageVersion: "*",
			},
			Scope: Scope{},
		},
		{
			Name:        demoPolicyPrefix + "Block suspected typosquats",
			Description: "Demo policy seeded on org creation. Blocks packages flagged as suspected typosquats of popular package names (e.g. 'lodahs' for 'lodash'). Catches lookalike-name attacks before they reach a developer's machine. Edit or delete this rule once you've seen it fire.",
			Mode:        ModeBlock,
			Status:      StatusEnabled,
			Conditions: Conditions{
				IsSuspectedTyposquat: &isTyposquatTrue,
			},
			Identifier: Identifier{
				TargetPackageRepo:    "*",
				TargetPackageName:    "*",
				TargetPackageVersion: "*",
			},
			Scope: Scope{},
		},
	}
}

// IsDemoPolicy reports whether the policy name was seeded by
// DemoPolicies(). Useful for activation telemetry — distinguishes a
// "first block on a seeded demo rule" from a "first block on an
// operator-defined rule".
func IsDemoPolicy(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), demoPolicyPrefix)
}

// SeedDemoPoliciesIfNeededTx seeds DemoPolicies() into the org inside
// the provided transaction. Idempotent — re-runs against an org that
// already has the named demo policies are no-ops. Caller is
// responsible for invalidating any in-process policy cache after a
// successful create.
//
// Precedence is allocated as MAX(existing) + i to slot the demo rules
// just above any operator-defined config policies and avoid colliding
// with the (org_id, precedence) UNIQUE index.
func SeedDemoPoliciesIfNeededTx(tx *sql.Tx, orgID string, logger *slog.Logger) (created int, err error) {
	if tx == nil {
		return 0, nil
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	base, err := nextPrecedenceTx(tx, orgID)
	if err != nil {
		return 0, fmt.Errorf("demo policies: allocate precedence: %w", err)
	}
	policies := DemoPolicies()
	for i := range policies {
		policies[i].Precedence = base + i
	}
	created, err = seedPolicies(tx, orgID, policies)
	if err != nil {
		return created, fmt.Errorf("demo policies: %w", err)
	}
	if created > 0 && logger != nil {
		logger.Info("seeded demo policies for org", "org_id", orgID, "count", created)
	}
	return created, nil
}

// nextPrecedenceTx returns one past the maximum precedence currently
// in use for the org, or 0 if no policies exist yet. Reads through
// the same executor interface seedPolicies uses so it composes inside
// the caller's transaction.
func nextPrecedenceTx(execer policyExecutor, orgID string) (int, error) {
	rows, err := execer.Query(`SELECT MAX(precedence) FROM policies WHERE org_id=?`, orgID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var maxVal sql.NullInt64
	if rows.Next() {
		if scanErr := rows.Scan(&maxVal); scanErr != nil {
			return 0, scanErr
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if !maxVal.Valid {
		return 0, nil
	}
	return int(maxVal.Int64) + 1, nil
}
