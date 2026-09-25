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
	// hasn't been used to launch an instance for six months.
	keepaliveCutoff = 183 * 24 * time.Hour
	// How far ahead of either deadline to act, so that a missed run or two
	// doesn't cost us an AMI. Applied to the last-launch clock and to the
	// deprecation date alike: an AMI that is already six months idle when it
	// deprecates is eligible for unsharing the moment the date passes, so
	// waiting for it to pass concedes a window.
	keepaliveBuffer = 14 * 24 * time.Hour

	// How long to wait for a keepalive instance to reach "running". Instances
	// normally get there in well under a minute; this is just a bound.
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
An AMI counts as at-risk once it is deprecated, or close to it, and has not been
launched in six months. AMIs with no reported last-launch time count as at-risk.

Note that AWS delays reporting a launch by up to 24 hours, so an AMI launched
on one run may still look at-risk on the next one and get launched again.

Keepalive instances are terminated before this exits, including on SIGINT and
SIGTERM. Any that survive a hard kill are tagged CreatedBy=mantle and are
collected by a later "ore aws gc" in the same region.

Exits non-zero if any AMI could not be restored or relaunched.

Examples:

  # Restore and relaunch at-risk production AMIs in a region
  ore aws ensure-public --region us-east-1

  # Report what would happen, without changing anything
  ore aws ensure-public --region us-east-1 --dry-run

  # Target a specific AMI by ID
  ore aws ensure-public --region us-east-1 --ami ami-0abc123`,
		RunE:         runEnsurePublic,
		Args:         cobra.NoArgs,
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
	if ensurePublicMaxLaunches < 0 {
		return fmt.Errorf("--max-launches cannot be negative")
	}

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
	reportedLaunch := 0
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
		if t.lastLaunch != nil {
			reportedLaunch++
		}

		// Image.Public is the all-group launch permission, so the list response
		// already tells us what a per-AMI DescribeImageAttribute would.
		t.needsPublic = img.Public == nil || !*img.Public

		// AWS only revokes public access after an AMI's deprecation date, so an
		// AMI that isn't near that date yet is not at risk. An AMI that has
		// already lost public access needs a launch either way: restoring it
		// without one just gets it revoked again. And naming a single AMI with
		// --ami means "do it".
		stale := t.lastLaunch == nil || time.Since(*t.lastLaunch) >= keepaliveCutoff-keepaliveBuffer
		t.needsLaunch = ensurePublicAMI != "" || t.needsPublic ||
			(isDeprecating(t.deprecation) && stale)

		if t.needsPublic || t.needsLaunch {
			targets = append(targets, t)
		}
	}

	// Every decision here rests on DescribeImages reporting LastLaunchedTime.
	// If it silently stopped doing so, nothing would fail: every AMI would just
	// look never-launched forever, and we'd relaunch the same capped batch
	// every day without ever converging. Say so rather than letting it pass.
	if len(images) > 1 && reportedLaunch == 0 {
		fmt.Fprintf(os.Stderr,
			"warning: none of the %d production AMIs in %s reports a last-launch time; "+
				"treating them all as at-risk\n", len(images), region)
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
		// Restoring public access without a launch only buys until AWS's next
		// sweep, so say plainly that the deferred AMIs aren't fixed yet: "N
		// restored" on its own reads like the problem is solved.
		fmt.Printf("%d AMIs at risk; launching %d now, deferring %d to a later run "+
			"(deferred AMIs may lose public access again before then)\n",
			len(atRisk), ensurePublicMaxLaunches, len(atRisk)-ensurePublicMaxLaunches)
		atRisk = atRisk[:ensurePublicMaxLaunches]
	}

	var errs []error

	// launched maps each keepalive instance to the AMI it came from. Nothing
	// here runs concurrently, so a plain map is enough: the interrupt handler
	// only cancels a context, and cleanup happens on this goroutine.
	launched := map[string]target{}
	interruptCtx, stopInterrupts := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopInterrupts()
	// Terminate on its own context rather than interruptCtx, so that a signal
	// is what triggers cleanup instead of what prevents it.
	cleanup := func() error {
		if len(launched) == 0 {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), keepaliveCleanupTimeout)
		defer cancel()
		if err := API.TerminateInstancesWithContext(ctx, instanceIDs(launched)); err != nil {
			return err
		}
		clear(launched)
		return nil
	}
	// Keep a best-effort retry for panic and cleanup-failure paths. Normal
	// cleanup below is explicit so its error affects the command exit status.
	defer func() {
		if err := cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "error terminating keepalive instances %v: %v\n", instanceIDs(launched), err)
		}
	}()

	for i, t := range atRisk {
		// Checking once per iteration is enough: an interrupt arriving mid-launch
		// is picked up before the next one starts, and anything already launched
		// is recorded and gets terminated on the way out.
		if interruptCtx.Err() != nil {
			fmt.Fprintln(os.Stderr, "interrupted; stopping keepalive launches and cleaning up")
			break
		}
		if ensurePublicDryRun {
			fmt.Printf("would launch %s (%s) — last launched %s\n",
				t.id, t.name, formatLastLaunch(t.lastLaunch))
			continue
		}
		instanceID, instanceType, err := API.LaunchKeepaliveInstance(t.id, t.arch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error launching keepalive for %s (%s): %v\n", t.id, t.name, err)
			errs = append(errs, fmt.Errorf("launching keepalive for %s: %v", t.id, err))
			// Out of instance quota: every remaining AMI would fail the same
			// way, so stop rather than turning one problem into a page of
			// identical errors. The AMIs we skip are picked up by a later run,
			// once someone has raised the quota.
			if errors.Is(err, aws.ErrInstanceQuotaExceeded) {
				fmt.Fprintf(os.Stderr, "out of instance quota in %s; skipping the remaining %d AMI(s)\n",
					region, len(atRisk)-i-1)
				break
			}
			continue
		}
		launched[instanceID] = t
		fmt.Printf("launched %s from %s (%s) %s — last launched %s\n",
			instanceID, t.id, t.name, instanceType, formatLastLaunch(t.lastLaunch))
	}

	if ids := instanceIDs(launched); len(ids) > 0 {
		// Wait for the instances to reach running before tearing them down. The
		// launch is already recorded against the AMI by this point; what the
		// wait buys is noticing an AMI that EC2 accepts but can't actually boot,
		// which would otherwise go unreported. Reaching running does not prove
		// the guest OS is healthy.
		if interruptCtx.Err() == nil {
			failures, err := API.WaitForInstancesRunning(interruptCtx, ids, keepaliveLaunchTimeout)
			if err != nil {
				// We couldn't read the states at all, so we know nothing about
				// any individual instance. Report that once, not once per ID.
				fmt.Fprintf(os.Stderr, "%v\n", err)
				errs = append(errs, err)
			}
			// Walk ids rather than the map so the order is stable from run to run.
			for _, id := range ids {
				failure, ok := failures[id]
				if !ok {
					continue
				}
				t := launched[id]
				fmt.Fprintf(os.Stderr, "keepalive %s for %s (%s) failed to start: %v\n", id, t.id, t.name, failure)
				errs = append(errs, fmt.Errorf("keepalive %s for %s failed to start: %v", id, t.id, failure))
			}
		}
		if err := cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "error terminating keepalive instances %v: %v\n", ids, err)
			errs = append(errs, fmt.Errorf("terminating keepalive instances %v: %v", ids, err))
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

// instanceIDs returns the keys of a launched-instance map in a stable order.
func instanceIDs(launched map[string]target) []string {
	ids := make([]string, 0, len(launched))
	for id := range launched {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// isDeprecating reports whether an AMI is past its deprecation date or will be
// within keepaliveBuffer.
func isDeprecating(deprecation string) bool {
	t := parseAWSTime(deprecation)
	return t != nil && t.Before(time.Now().Add(keepaliveBuffer))
}

// parseAWSTime parses an EC2 API timestamp, returning nil if it's absent or
// unparseable. Go accepts a fractional second even though RFC3339 doesn't
// spell one out, so this handles both of the forms EC2 uses.
func parseAWSTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// describeDeprecation renders an AMI's deprecation date for logging
func (t target) describeDeprecation() string {
	if t.deprecation == "" {
		return "no deprecation date"
	}
	date := t.deprecation
	if parsed := parseAWSTime(date); parsed != nil {
		date = parsed.Format("2006-01-02")
	}
	return fmt.Sprintf("deprecation date %s", date)
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
