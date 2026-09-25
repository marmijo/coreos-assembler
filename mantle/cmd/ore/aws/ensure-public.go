// Copyright 2026 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/cobra"

	"github.com/coreos/coreos-assembler/mantle/platform/api/aws"
)

const (
	// AWS removes the public sharing property from a deprecated AMI once it
	// hasn't been used to launch an instance for six months. Relaunch a bit
	// ahead of that so a missed run or two doesn't cost us the AMI.
	keepaliveCutoff = 183 * 24 * time.Hour
	keepaliveBuffer = 14 * 24 * time.Hour

	// How long to wait for a keepalive instance to leave "pending". Instances
	// normally reach "running" in well under a minute; this is just a bound.
	keepaliveLaunchTimeout  = 5 * time.Minute
	keepaliveCleanupTimeout = 30 * time.Second
)

var (
	cmdEnsurePublic = &cobra.Command{
		Use:   "ensure-public",
		Short: "Ensure production RHCOS AMIs remain publicly accessible",
		Long: `Keeps production RHCOS AMIs (tagged production=true) publicly accessible
despite AWS's automatic AMI deprecation policy.

AWS gives public AMIs a default deprecation date 2 years after creation and
eventually removes their public sharing permission after deprecation when no
instances have been launched for 6+ months.
This breaks OpenShift customers trying to scale cluster nodes with older images.
DisableImageDeprecation has no effect on public AMIs.

Restoring the launch permission alone is not enough: with no launches, AWS just
revokes it again. So this also launches and immediately terminates a throwaway
instance from each at-risk AMI, recording activity for AWS's inactivity policy.
AMIs with no reported last-launch time count as at-risk.

Note that AWS delays reporting a launch by up to 24 hours, so an AMI launched
on one run may still look at-risk on the next one and get launched again.

Exits non-zero if any AMI could not be restored or relaunched.

Examples:

  # Restore and relaunch at-risk production AMIs in a region
  ore aws ensure-public --region us-east-1

  # Report what would happen, without changing anything
  ore aws ensure-public --region us-east-1 --dry-run

  # Target a specific AMI by ID
  ore aws ensure-public --region us-east-1 --ami ami-0abc123`,
		RunE: runEnsurePublic,
		Args: func(cmd *cobra.Command, args []string) error {
			return validateEnsurePublicOptions(args)
		},
		SilenceUsage: true,
	}

	ensurePublicAMI         string
	ensurePublicDryRun      bool
	ensurePublicNoLaunch    bool
	ensurePublicMaxLaunches int
)

func init() {
	AWS.AddCommand(cmdEnsurePublic)
	cmdEnsurePublic.Flags().StringVar(&ensurePublicAMI, "ami", "",
		"Target a single AMI by ID; bypasses the production=true tag filter.")
	cmdEnsurePublic.Flags().BoolVar(&ensurePublicDryRun, "dry-run", false,
		"Report what would be restored and launched without changing anything.")
	cmdEnsurePublic.Flags().BoolVar(&ensurePublicNoLaunch, "no-launch", false,
		"Only restore public permissions; don't launch keepalive instances.")
	cmdEnsurePublic.Flags().IntVar(&ensurePublicMaxLaunches, "max-launches", 25,
		"Maximum keepalive instances to launch per run; 0 for no limit.")
}

func validateEnsurePublicOptions(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("ensure-public accepts no positional arguments")
	}
	if ensurePublicMaxLaunches < 0 {
		return fmt.Errorf("--max-launches cannot be negative")
	}
	return nil
}

// target is an AMI we've decided to act on, and what needs doing to it.
type target struct {
	id          string
	name        string
	arch        ec2types.ArchitectureValues
	deprecation string
	// lastLaunch is nil when the AMI has never been launched.
	lastLaunch  *time.Time
	needsPublic bool
	needsLaunch bool
}

func runEnsurePublic(cmd *cobra.Command, args []string) error {
	targets, err := ensurePublicTargets()
	if err != nil {
		return err
	}

	// Work through every AMI before returning, so that one failure doesn't
	// skip the rest. Errors go to stderr as we hit them, and are collected
	// into the returned error so the command still exits non-zero.
	var errs []error
	restoreFailures := 0

	for _, t := range targets {
		if !t.needsPublic {
			continue
		}
		if ensurePublicDryRun {
			fmt.Printf("would restore %s (%s) — %s\n", t.id, t.name, t.describeDeprecation())
			continue
		}
		if err := API.RestoreImagePublic(t.id); err != nil {
			fmt.Fprintf(os.Stderr, "error restoring %s (%s): %v\n", t.id, t.name, err)
			restoreFailures++
			continue
		}
		fmt.Printf("restored %s (%s) — %s\n", t.id, t.name, t.describeDeprecation())
	}
	if restoreFailures > 0 {
		errs = append(errs, fmt.Errorf("%d AMI(s) could not be made public", restoreFailures))
	}

	if !ensurePublicNoLaunch {
		if err := launchKeepaliveInstances(targets); err != nil {
			errs = append(errs, err)
		}
	}

	// Join returns nil when there's nothing to report, so a clean run exits 0.
	return errors.Join(errs...)
}

// ensurePublicTargets returns only the AMIs that need something done to them:
// their public launch permission restored, a keepalive launch to reset AWS's
// last-launched clock, or both. AMIs that are fine are not returned.
func ensurePublicTargets() ([]target, error) {
	var images []ec2types.Image
	if ensurePublicAMI != "" {
		img, err := API.GetImageByID(ensurePublicAMI)
		if err != nil {
			return nil, fmt.Errorf("fetching AMI %s: %v", ensurePublicAMI, err)
		}
		if img == nil {
			return nil, fmt.Errorf("AMI %s not found in region %s", ensurePublicAMI, region)
		}
		images = []ec2types.Image{*img}
	} else {
		var err error
		images, err = API.ListProductionImages()
		if err != nil {
			return nil, fmt.Errorf("listing production AMIs in %s: %v", region, err)
		}
	}

	targets := make([]target, 0, len(images))
	for _, img := range images {
		t := target{
			id:          derefStr(img.ImageId),
			name:        derefStr(img.Name),
			arch:        img.Architecture,
			deprecation: derefStr(img.DeprecationTime),
			lastLaunch:  parseAWSTime(derefStr(img.LastLaunchedTime)),
		}
		if t.id == "" {
			// Not something DescribeImages should return, but we can't act on it.
			fmt.Fprintf(os.Stderr, "skipping image with no ID\n")
			continue
		}

		// Image.Public is the all-group launch permission, so the list response
		// already tells us what a per-AMI DescribeImageAttribute would.
		t.needsPublic = img.Public == nil || !*img.Public

		// AWS only revokes public access once an AMI is past its deprecation
		// date, so a still-current AMI is never at risk. An AMI that has
		// already lost public access needs a launch either way: restoring it
		// without one just gets it revoked again. And naming a single AMI with
		// --ami means "do it".
		stale := t.lastLaunch == nil || time.Since(*t.lastLaunch) >= keepaliveCutoff-keepaliveBuffer
		t.needsLaunch = ensurePublicAMI != "" || t.needsPublic ||
			(isDeprecated(t.deprecation) && stale)

		if t.needsPublic || t.needsLaunch {
			targets = append(targets, t)
		}
	}
	return targets, nil
}

// launchKeepaliveInstances launches, waits on, and terminates one throwaway instance
// per at-risk AMI, so that AWS records a recent launch against it. Instances
// are launched as a batch and waited on together: waiting out each boot in turn
// would take far longer than a daily run can afford. It returns an error
// summarizing every failure, or nil if everything succeeded.
func launchKeepaliveInstances(targets []target) error {
	atRisk := make([]target, 0, len(targets))
	for _, t := range targets {
		if t.needsLaunch {
			atRisk = append(atRisk, t)
		}
	}
	if len(atRisk) == 0 {
		return nil
	}

	// Most urgent first, so that a capped run works on the AMIs closest to
	// losing their public sharing property. Never-launched AMIs sort first.
	sort.SliceStable(atRisk, func(i, j int) bool {
		a, b := atRisk[i].lastLaunch, atRisk[j].lastLaunch
		if a == nil || b == nil {
			return a == nil && b != nil
		}
		return a.Before(*b)
	})
	if ensurePublicMaxLaunches > 0 && len(atRisk) > ensurePublicMaxLaunches {
		fmt.Printf("%d AMIs at risk; launching %d now, deferring %d to the next run\n",
			len(atRisk), ensurePublicMaxLaunches, len(atRisk)-ensurePublicMaxLaunches)
		atRisk = atRisk[:ensurePublicMaxLaunches]
	}

	var errs []error

	tracker := newKeepaliveTracker(API.TerminateInstancesWithContext)
	byID := map[string]target{}
	interruptCtx, stopInterrupts := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopInterrupts()
	cleanup := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), keepaliveCleanupTimeout)
		defer cancel()
		return tracker.cleanup(ctx)
	}
	// Keep a best-effort retry for panic and cleanup-failure paths. Normal
	// cleanup below is explicit so its error affects the command exit status.
	defer func() {
		if err := cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "error terminating keepalive instances %v: %v\n", tracker.ids(), err)
		}
	}()

	for _, t := range atRisk {
		// Checking once per iteration is enough: an interrupt arriving mid-launch
		// is picked up before the next one starts, and anything already launched
		// is in the tracker and gets terminated on the way out.
		if interruptCtx.Err() != nil {
			fmt.Fprintln(os.Stderr, "interrupted; stopping keepalive launches and cleaning up")
			break
		}
		if ensurePublicDryRun {
			instanceType, err := aws.KeepaliveInstanceType(t.arch)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot launch %s (%s): %v\n", t.id, t.name, err)
				errs = append(errs, fmt.Errorf("no keepalive instance type for %s: %v", t.id, err))
				continue
			}
			fmt.Printf("would launch %s (%s) %s — last launched %s\n",
				t.id, t.name, instanceType, formatLastLaunch(t.lastLaunch))
			continue
		}
		instanceID, instanceType, err := API.LaunchKeepaliveInstance(t.id, t.arch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error launching keepalive for %s (%s): %v\n", t.id, t.name, err)
			errs = append(errs, fmt.Errorf("launching keepalive for %s: %v", t.id, err))
			continue
		}
		tracker.add(instanceID)
		byID[instanceID] = t
		fmt.Printf("launched %s from %s (%s) %s — last launched %s\n",
			instanceID, t.id, t.name, instanceType, formatLastLaunch(t.lastLaunch))
	}

	if ids := tracker.ids(); len(ids) > 0 {
		// Wait for the launch to actually take effect before tearing it down: an
		// instance that goes straight from pending to terminated was not accepted
		// as a usable launch by EC2, which is worth reporting. Reaching running
		// does not prove that the guest OS or its applications are healthy.
		results := map[string]error{}
		if interruptCtx.Err() == nil {
			var err error
			results, err = API.WaitForInstancesLeavePending(interruptCtx, ids, keepaliveLaunchTimeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				errs = append(errs, err)
			}
		}
		// Walk ids rather than byID so the order is stable from run to run.
		for _, id := range ids {
			t := byID[id]
			result, settled := results[id]
			switch {
			case !settled && interruptCtx.Err() == nil:
				fmt.Fprintf(os.Stderr, "keepalive %s for %s (%s) never left pending\n", id, t.id, t.name)
				errs = append(errs, fmt.Errorf("keepalive %s for %s never left pending", id, t.id))
			case result != nil:
				fmt.Fprintf(os.Stderr, "keepalive %s for %s (%s) failed to start: %v\n", id, t.id, t.name, result)
				errs = append(errs, fmt.Errorf("keepalive %s for %s failed to start: %v", id, t.id, result))
			}
		}
		if err := cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "error terminating keepalive instances %v: %v\n", tracker.ids(), err)
			errs = append(errs, fmt.Errorf("terminating keepalive instances %v: %v", tracker.ids(), err))
		} else {
			fmt.Printf("requested termination of keepalive instances %v\n", ids)
		}
	}

	// Reported once at the end, whether the signal arrived during the launch
	// loop or the wait above.
	if interruptCtx.Err() != nil {
		errs = append(errs, errors.New("interrupted before every at-risk AMI was relaunched"))
	}

	return errors.Join(errs...)
}

type keepaliveTracker struct {
	instanceIDs []string
	terminate   func(context.Context, []string) error
}

func newKeepaliveTracker(terminate func(context.Context, []string) error) *keepaliveTracker {
	return &keepaliveTracker{terminate: terminate}
}

func (t *keepaliveTracker) add(id string) {
	t.instanceIDs = append(t.instanceIDs, id)
}

func (t *keepaliveTracker) ids() []string {
	ids := append([]string(nil), t.instanceIDs...)
	sort.Strings(ids)
	return ids
}

func (t *keepaliveTracker) cleanup(ctx context.Context) error {
	ids := t.ids()
	if len(ids) == 0 {
		return nil
	}
	if err := t.terminate(ctx, ids); err != nil {
		return err
	}
	t.instanceIDs = nil
	return nil
}

// isDeprecated reports whether an AMI is past the given deprecation date. A
// missing or unparseable date counts as not deprecated: AWS only revokes public
// access after deprecation, so there's nothing for us to get ahead of.
func isDeprecated(deprecation string) bool {
	t := parseAWSTime(deprecation)
	return t != nil && t.Before(time.Now())
}

// parseAWSTime parses an EC2 API timestamp, returning nil if it's absent or
// unparseable. These are ISO 8601, but AWS is inconsistent about the
// fractional seconds, so try a few layouts.
func parseAWSTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// describeDeprecation renders an AMI's deprecation date for logging, e.g.
// "deprecated on 2025-01-15".
func (t target) describeDeprecation() string {
	if t.deprecation == "" {
		return "no deprecation date"
	}
	if parsed := parseAWSTime(t.deprecation); parsed != nil {
		return fmt.Sprintf("deprecated on %s", parsed.Format("2006-01-02"))
	}
	return fmt.Sprintf("deprecated on %s", t.deprecation)
}

func formatLastLaunch(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format("2006-01-02")
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
