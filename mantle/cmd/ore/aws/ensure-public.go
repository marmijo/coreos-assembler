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
	// AWS unshares a deprecated AMI once it hasn't been launched for six months.
	keepaliveCutoff = 183 * 24 * time.Hour
	// How far ahead of either deadline to act, so a missed run or two doesn't
	// cost us an AMI. Applied to the deprecation date too: an AMI already six
	// months idle when it deprecates can be unshared the moment the date passes.
	keepaliveBuffer = 14 * 24 * time.Hour

	// Bound on the wait for "running"; instances get there in under a minute.
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
Restore and relaunch always act on the same AMIs, so --max-launches caps both.

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
		"Maximum AMIs to act on per run, most urgent first; 0 for no limit.")
}

// target is an at-risk AMI this run will launch a keepalive instance from.
// needsPublic means AWS has already taken its public sharing permission away.
type target struct {
	id          string
	name        string
	arch        ec2types.ArchitectureValues
	deprecation string
	// lastLaunch is nil when the AMI has never been launched.
	lastLaunch  *time.Time
	needsPublic bool
}

func runEnsurePublic(cmd *cobra.Command, args []string) error {
	if ensurePublicMaxLaunches < 0 {
		return fmt.Errorf("--max-launches cannot be negative")
	}

	targets, err := ensurePublicTargets()
	if err != nil {
		return err
	}

	// Restoring an AMI without launching from it just gets the permission
	// revoked again, so both halves work from one ordered, capped list rather
	// than each picking its own and drifting apart.
	sortByUrgency(targets)
	if !ensurePublicNoLaunch {
		targets = capWorkList(targets)
	}

	// Work through every AMI before returning. Errors go to stderr as we hit
	// them and are collected so the command still exits non-zero.
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

// ensurePublicTargets returns the AMIs at risk of losing public access: those
// needing their launch permission restored, a keepalive launch, or both.
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

		// AWS only unshares after the deprecation date, so an AMI far from it
		// is safe. One that already lost public access is at risk regardless:
		// restoring it without a launch just gets it revoked. --ami means "do it".
		stale := t.lastLaunch == nil || time.Since(*t.lastLaunch) >= keepaliveCutoff-keepaliveBuffer
		atRisk := ensurePublicAMI != "" || t.needsPublic ||
			(isDeprecating(t.deprecation) && stale)

		if atRisk {
			targets = append(targets, t)
		}
	}

	// If DescribeImages silently stopped reporting LastLaunchedTime, nothing
	// would fail: every AMI would look never-launched and we'd relaunch the
	// same capped batch daily without converging. Say so instead.
	if len(images) > 1 && reportedLaunch == 0 {
		fmt.Fprintf(os.Stderr,
			"warning: none of the %d production AMIs in %s reports a last-launch time; "+
				"treating them all as at-risk\n", len(images), region)
	}

	return targets, nil
}

// sortByUrgency orders AMIs most-urgent-first, so a capped run spends its
// budget on the ones closest to losing public access.
func sortByUrgency(targets []target) {
	sort.SliceStable(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		// Already unshared: broken for customers now, and the restore this run
		// performs is undone without the paired launch.
		if a.needsPublic != b.needsPublic {
			return a.needsPublic
		}
		// Never launched, so there's no clock left to run down.
		if (a.lastLaunch == nil) != (b.lastLaunch == nil) {
			return a.lastLaunch == nil
		}
		if a.lastLaunch == nil {
			return false
		}
		return a.lastLaunch.Before(*b.lastLaunch)
	})
}

// capWorkList trims the run to --max-launches AMIs. Restores are capped along
// with launches: restoring an AMI we won't launch only gets it unshared again.
func capWorkList(targets []target) []target {
	if ensurePublicMaxLaunches <= 0 || len(targets) <= ensurePublicMaxLaunches {
		return targets
	}
	// Spell out that the deferred AMIs aren't fixed yet; a bare count of what
	// this run did reads like the whole backlog is handled.
	fmt.Printf("%d AMIs at risk; acting on %d now, deferring %d to a later run "+
		"(deferred AMIs stay at risk until then)\n",
		len(targets), ensurePublicMaxLaunches, len(targets)-ensurePublicMaxLaunches)
	return targets[:ensurePublicMaxLaunches]
}

// launchKeepaliveInstances launches, waits on, and terminates one throwaway
// instance per AMI, so AWS records a recent launch against it. They go up as a
// batch and are waited on together; serializing the boots would take far longer
// than a daily run can afford. The caller has already ordered and capped the
// list. Returns an error summarizing every failure, or nil if all succeeded.
func launchKeepaliveInstances(targets []target) error {
	if len(targets) == 0 {
		return nil
	}

	var errs []error

	// launched maps each keepalive instance to its AMI. Nothing here runs
	// concurrently, so a plain map is enough: the interrupt handler only
	// cancels a context, and cleanup happens on this goroutine.
	launched := map[string]target{}
	interruptCtx, stopInterrupts := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopInterrupts()
	// Its own context, not interruptCtx, so a signal triggers cleanup instead
	// of preventing it.
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
	// Backstop for panics; the explicit call below sets the exit status.
	defer func() {
		if err := cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "error terminating keepalive instances %v: %v\n", instanceIDs(launched), err)
		}
	}()

	for i, t := range targets {
		// Once per iteration is enough: an interrupt mid-launch is caught before
		// the next one, and what's launched is recorded and cleaned up on exit.
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
			// Properties of the region, not of one AMI — no quota left, no
			// default VPC — so every remaining AMI fails identically. Stop
			// instead of printing a page of the same error; a later run
			// picks them up once someone has fixed it.
			if errors.Is(err, aws.ErrInstanceQuotaExceeded) || errors.Is(err, aws.ErrNoDefaultVPC) {
				fmt.Fprintf(os.Stderr, "skipping the remaining %d AMI(s) in %s\n",
					len(targets)-i-1, region)
				break
			}
			continue
		}
		launched[instanceID] = t
		fmt.Printf("launched %s from %s (%s) %s — last launched %s\n",
			instanceID, t.id, t.name, instanceType, formatLastLaunch(t.lastLaunch))
	}

	if ids := instanceIDs(launched); len(ids) > 0 {
		// Wait for running before tearing them down. The launch is already
		// recorded by this point; the wait catches an AMI that EC2 accepts but
		// can't boot. Running does not prove the guest OS is healthy.
		if interruptCtx.Err() == nil {
			failures, err := API.WaitForInstancesRunning(interruptCtx, ids, keepaliveLaunchTimeout)
			if err != nil {
				// No states read at all, so nothing is known per-instance.
				// Report that once, not once per ID.
				fmt.Fprintf(os.Stderr, "%v\n", err)
				errs = append(errs, err)
			}
			// Walk ids, not the map, so the order is stable run to run.
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

	// Reported once, whether the signal arrived during the loop or the wait.
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

// isDeprecating reports whether an AMI deprecates within keepaliveBuffer, or has.
func isDeprecating(deprecation string) bool {
	t := parseAWSTime(deprecation)
	return t != nil && t.Before(time.Now().Add(keepaliveBuffer))
}

// parseAWSTime parses an EC2 timestamp, returning nil if absent or unparseable.
// Go accepts the fractional second EC2 sometimes adds, so one layout covers both.
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
