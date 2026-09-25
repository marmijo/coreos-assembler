// Copyright 2016 CoreOS, Inc.
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
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"

	"github.com/coreos/coreos-assembler/mantle/util"
)

type RegionKind int

const (
	RegionEnabled RegionKind = iota
	RegionDisabled
	RegionAny
)

// ListRegions lists the enabled regions in the AWS partition specified
// implicitly by the CredentialsFile, Profile, and Region options.
func (a *API) ListRegions(kind RegionKind) ([]string, error) {
	input := ec2.DescribeRegionsInput{}
	switch kind {
	case RegionDisabled:
		input.AllRegions = aws.Bool(true)
		input.Filters = []ec2types.Filter{
			{
				Name:   aws.String("opt-in-status"),
				Values: []string{"not-opted-in"},
			},
		}
	case RegionAny:
		input.AllRegions = aws.Bool(true)
	}
	output, err := a.ec2.DescribeRegions(context.Background(), &input)
	if err != nil {
		return nil, fmt.Errorf("describing regions: %v", err)
	}
	ret := make([]string, 0, len(output.Regions))
	for _, region := range output.Regions {
		ret = append(ret, *region.RegionName)
	}
	sort.Strings(ret)
	return ret, nil
}

func (a *API) AddKey(name, key string) error {
	_, err := a.ec2.ImportKeyPair(context.Background(), &ec2.ImportKeyPairInput{
		KeyName:           &name,
		PublicKeyMaterial: []byte(key),
	})

	return err
}

func (a *API) DeleteKey(name string) error {
	_, err := a.ec2.DeleteKeyPair(context.Background(), &ec2.DeleteKeyPairInput{
		KeyName: &name,
	})

	return err
}

// CreateInstances creates EC2 instances with a given name tag, optional ssh key name, user data. The image ID, instance type, and security group set in the API will be used. CreateInstances will block until all instances are running and have an IP address.
func (a *API) CreateInstances(name, keyname, userdata string, count uint64, minDiskSize int64, useInstanceProfile bool) ([]ec2types.Instance, error) {
	cnt := int64(count)

	var ud *string
	if len(userdata) > 0 {
		tud := base64.StdEncoding.EncodeToString([]byte(userdata))
		ud = &tud
	}

	if useInstanceProfile {
		err := a.ensureInstanceProfile(a.opts.IAMInstanceProfile)
		if err != nil {
			return nil, fmt.Errorf("error verifying IAM instance profile: %v", err)
		}
	}

	sgId, err := a.getSecurityGroupID(a.opts.SecurityGroup)
	if err != nil {
		return nil, fmt.Errorf("error resolving security group: %v", err)
	}

	vpcId, err := a.getVPCID(sgId)
	if err != nil {
		return nil, fmt.Errorf("error resolving vpc: %v", err)
	}

	zones, err := a.GetZonesForInstanceType(a.opts.InstanceType)
	if err != nil {
		// Find all available zones that offer the given instance type
		return nil, fmt.Errorf("error finding zones for instance type %v", a.opts.InstanceType)
	}

	var reservations *ec2.RunInstancesOutput

	// Iterate over other possible zones if capacity for an instance
	// type is exhausted
	for zoneKey, zone := range zones {
		subnetId, err := a.getSubnetID(vpcId, zone)
		if err != nil {
			return nil, fmt.Errorf("error resolving subnet: %v", err)
		}

		key := &keyname
		if keyname == "" {
			key = nil
		}

		var rootBlockDev []ec2types.BlockDeviceMapping
		if minDiskSize > 0 {
			rootBlockDev = append(rootBlockDev, ec2types.BlockDeviceMapping{
				DeviceName: aws.String("/dev/xvda"),
				Ebs: &ec2types.EbsBlockDevice{
					VolumeSize: aws.Int32(int32(minDiskSize)),
				},
			})
		}
		inst := ec2.RunInstancesInput{
			ImageId:             &a.opts.AMI,
			MinCount:            aws.Int32(int32(cnt)),
			MaxCount:            aws.Int32(int32(cnt)),
			KeyName:             key,
			InstanceType:        ec2types.InstanceType(a.opts.InstanceType),
			SecurityGroupIds:    []string{sgId},
			SubnetId:            &subnetId,
			UserData:            ud,
			BlockDeviceMappings: rootBlockDev,
			TagSpecifications: []ec2types.TagSpecification{
				{
					ResourceType: ec2types.ResourceTypeInstance,
					Tags: []ec2types.Tag{
						{
							Key:   aws.String("Name"),
							Value: aws.String(name),
						},
						{
							Key:   aws.String("CreatedBy"),
							Value: aws.String("mantle"),
						},
					},
				},
			},
		}
		if useInstanceProfile {
			inst.IamInstanceProfile = &ec2types.IamInstanceProfileSpecification{
				Name: &a.opts.IAMInstanceProfile,
			}
		}

		err = util.RetryConditional(5, 5*time.Second, func(err error) bool {
			// due to AWS' eventual consistency despite ensuring that the IAM Instance
			// Profile has been created it may not be available to ec2 yet.
			var ae smithy.APIError
			if errors.As(err, &ae) && (ae.ErrorCode() == "InvalidParameterValue" && strings.Contains(ae.ErrorMessage(), "iamInstanceProfile.name")) {
				return true
			}
			return false
		}, func() error {
			var ierr error
			reservations, ierr = a.ec2.RunInstances(context.Background(), &inst)
			return ierr
		})
		if err == nil {
			// Successfully started our instance in the requested zone. Break out of the loop
			break
		} else {
			// Handle InsufficientInstanceCapacity error specifically
			var ae smithy.APIError
			if errors.As(err, &ae) && ae.ErrorCode() == "InsufficientInstanceCapacity" {
				// If we iterate over all possible zones and none of them have sufficient instance(s)
				// available we will return the InsufficientInstanceCapacity error
				if zoneKey == len(zones)-1 {
					return nil, fmt.Errorf("all available zones tried: %v", err)
				}
				plog.Warningf("Insufficient instances available in zone %v. Trying the next zone\n", zone)
				continue
			}
			return nil, fmt.Errorf("error running instances: %v", err)
		}
	}

	ids := make([]string, len(reservations.Instances))
	for i, inst := range reservations.Instances {
		ids[i] = *inst.InstanceId
	}

	// loop until all machines are online
	var insts []ec2types.Instance

	// 10 minutes is a pretty reasonable timeframe for AWS instances to work.
	timeout := 10 * time.Minute
	// don't make api calls too quickly, or we will hit the rate limit
	delay := 10 * time.Second
	err = util.WaitUntilReady(timeout, delay, func() (bool, error) {
		desc, err := a.ec2.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
			InstanceIds: ids,
		})
		if err != nil {
			// Keep retrying if the InstanceID disappears momentarily
			var ae smithy.APIError
			if errors.As(err, &ae) && ae.ErrorCode() == "InvalidInstanceID.NotFound" {
				plog.Debugf("instance ID not found, retrying: %v", err)
				return false, nil
			}
			return false, err
		}
		insts = desc.Reservations[0].Instances

		for _, i := range insts {
			if i.State.Name != ec2types.InstanceStateNameRunning || i.PublicIpAddress == nil {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		if errTerminate := a.TerminateInstances(ids); errTerminate != nil {
			return nil, fmt.Errorf("terminating instances failed: %v after instances failed to run: %v", errTerminate, err)
		}
		return nil, fmt.Errorf("waiting for instances to run: %v", err)
	}

	// add tags to all created volumes
	var volumes []string
	tagMap := map[string]string{
		"CreatedBy": "mantle",
	}
	for _, inst := range insts {
		if len(inst.BlockDeviceMappings) > 0 {
			for _, mapping := range inst.BlockDeviceMappings {
				if mapping.Ebs != nil && mapping.Ebs.VolumeId != nil {
					volumes = append(volumes, *mapping.Ebs.VolumeId)
				}
			}
		}
	}
	err = a.CreateTags(volumes, tagMap)
	if err != nil {
		return nil, fmt.Errorf("error adding tags to volumes: %v", err)
	}

	return insts, nil
}

// gcEC2 will terminate ec2 instances older than gracePeriod.
// It will only operate on ec2 instances tagged with 'mantle' to avoid stomping
// on other resources in the account.
func (a *API) gcEC2(gracePeriod time.Duration) error {
	durationAgo := time.Now().Add(-1 * gracePeriod)

	instances, err := a.ec2.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("tag:CreatedBy"),
				Values: []string{"mantle"},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("error describing instances: %v", err)
	}

	toTerminate := []string{}

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			if instance.LaunchTime.After(durationAgo) {
				plog.Debugf("ec2: skipping instance %s due to being too new", *instance.InstanceId)
				// Skip, still too new
				continue
			}

			if instance.State != nil {
				switch instance.State.Name {
				case ec2types.InstanceStateNamePending, ec2types.InstanceStateNameRunning, ec2types.InstanceStateNameStopped:
					toTerminate = append(toTerminate, *instance.InstanceId)
				case ec2types.InstanceStateNameTerminated, ec2types.InstanceStateNameShuttingDown:
				default:
					plog.Infof("ec2: skipping instance in state %s", string(instance.State.Name))
				}
			} else {
				plog.Warningf("ec2 instance had no state: %s", *instance.InstanceId)
			}
		}
	}

	return a.TerminateInstances(toTerminate)
}

// TerminateInstances schedules EC2 instances to be terminated.
func (a *API) TerminateInstances(ids []string) error {
	return a.TerminateInstancesWithContext(context.Background(), ids)
}

// TerminateInstancesWithContext schedules EC2 instances to be terminated.
func (a *API) TerminateInstancesWithContext(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	input := &ec2.TerminateInstancesInput{
		InstanceIds: ids,
	}

	if _, err := a.ec2.TerminateInstances(ctx, input); err != nil {
		return err
	}

	return nil
}

func (a *API) CreateTags(resources []string, tags map[string]string) error {
	if len(tags) == 0 {
		return nil
	}

	tagObjs := make([]ec2types.Tag, 0, len(tags))
	for key, value := range tags {
		tagObjs = append(tagObjs, ec2types.Tag{
			Key:   aws.String(key),
			Value: aws.String(value),
		})
	}
	_, err := a.ec2.CreateTags(context.Background(), &ec2.CreateTagsInput{
		Resources: resources,
		Tags:      tagObjs,
	})
	if err != nil {
		return fmt.Errorf("error creating tags: %v", err)
	}
	return err
}

// GetConsoleOutput returns the console output. Returns "", nil if no logs
// are available.
func (a *API) GetConsoleOutput(instanceID string) (string, error) {
	res, err := a.ec2.GetConsoleOutput(context.Background(), &ec2.GetConsoleOutputInput{
		InstanceId: aws.String(instanceID),
	})
	if err != nil {
		return "", fmt.Errorf("couldn't get console output of %v: %v", instanceID, err)
	}

	if res.Output == nil {
		return "", nil
	}

	decoded, err := base64.StdEncoding.DecodeString(*res.Output)
	if err != nil {
		return "", fmt.Errorf("couldn't decode console output of %v: %v", instanceID, err)
	}

	return string(decoded), nil
}

// GetZonesForInstanceType returns all available zones that offer the
// given instance type. This is useful because not all availability zones
// offer all instances types.
func (a *API) GetZonesForInstanceType(instanceType string) ([]string, error) {

	input := ec2.DescribeInstanceTypeOfferingsInput{
		LocationType: ec2types.LocationTypeAvailabilityZone,
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("instance-type"),
				Values: []string{instanceType},
			},
		},
	}
	output, err := a.ec2.DescribeInstanceTypeOfferings(context.Background(), &input)
	if err != nil {
		return nil, fmt.Errorf("error describing instance offerings: %v", err)
	}
	if len(output.InstanceTypeOfferings) == 0 {
		return nil, fmt.Errorf("no availability zones found for this instance type %v:", instanceType)
	}

	var zones []string
	for _, v := range output.InstanceTypeOfferings {
		zones = append(zones, *v.Location)
	}
	return zones, nil
}

// KeepalivePurpose is the value of the Purpose tag on throwaway instances
// launched to keep an AMI active, telling them apart from kola's in the
// console. gcEC2 collects both, matching the CreatedBy=mantle tag these carry.
const KeepalivePurpose = "ami-keepalive"

// keepaliveRunTimeout bounds one RunInstances attempt, SDK retries included, so
// a hung call can't stall a run that has every at-risk AMI in a region to get
// through. RunInstances normally answers in a few seconds.
const keepaliveRunTimeout = 30 * time.Second

// ErrInstanceQuotaExceeded reports that the account is out of on-demand
// capacity in this region. Every subsequent launch would fail the same way, so
// callers should stop rather than work through the rest of their list.
var ErrInstanceQuotaExceeded = errors.New("on-demand instance quota exceeded")

// ErrNoDefaultVPC reports that the region has no default VPC to launch into.
// Like a quota failure this is a property of the region, not of one AMI, so
// callers should stop rather than work through the rest of their list.
//
// AWS creates a default VPC when an account enables a region, so this should
// not happen. If it does — a newly onboarded region, or one where someone
// deleted the default VPC by hand — recreate it with:
//
//	aws ec2 create-default-vpc --region <region>
var ErrNoDefaultVPC = errors.New("region has no default VPC")

// keepaliveInstanceTypes lists, per architecture, the instance types to try,
// cheapest first. All Nitro, so they can boot UEFI images; aarch64 CoreOS AMIs
// are always registered with a UEFI boot mode (see CreateHVMImage). The
// burstable types come first as broadly available and cheap; the second entry
// is a different family, tried if the first isn't offered or has no capacity.
var keepaliveInstanceTypes = map[ec2types.ArchitectureValues][]string{
	ec2types.ArchitectureValuesX8664: {"t3.micro", "m6i.large"},
	ec2types.ArchitectureValuesArm64: {"t4g.micro", "m6g.medium"},
}

// LaunchKeepaliveInstance launches one throwaway instance from the given AMI,
// purely so AWS records a launch against it, and returns the instance ID and
// the instance type that worked. The caller must terminate the instance.
//
// Unlike CreateInstances it attaches no key pair and no user data, and doesn't
// wait for reachability, because nothing ever logs in. It uses the region's
// default VPC, so it needs no network of its own and leaves nothing behind.
//
// A failure that would defeat any further launch in this region is returned
// wrapping ErrInstanceQuotaExceeded or ErrNoDefaultVPC.
func (a *API) LaunchKeepaliveInstance(imageID string, arch ec2types.ArchitectureValues) (string, string, error) {
	types := keepaliveInstanceTypes[arch]
	if len(types) == 0 {
		return "", "", fmt.Errorf("no keepalive instance types known for architecture %q", string(arch))
	}

	var attempts []string
	for _, instanceType := range types {
		res, err := a.runKeepaliveInstance(imageID, instanceType)
		if err == nil {
			if res == nil || len(res.Instances) == 0 || res.Instances[0].InstanceId == nil {
				return "", "", fmt.Errorf("launching keepalive instance from %v: no instance returned", imageID)
			}
			return *res.Instances[0].InstanceId, instanceType, nil
		}
		attempts = append(attempts, fmt.Sprintf("%v: %v", instanceType, err))
		if isNoDefaultVPCError(err) {
			// Not the instance type's doing, and no later run fixes it by
			// itself: someone has to create the default VPC.
			return "", "", fmt.Errorf("launching keepalive instance from %v: %w; "+
				"create one with \"aws ec2 create-default-vpc --region %v\": %v",
				imageID, ErrNoDefaultVPC, a.opts.Region, strings.Join(attempts, "; "))
		}
		if isInstanceQuotaError(err) {
			// Another type wouldn't help: the quota counts vCPUs across the
			// family, and the fallback types are no smaller.
			return "", "", fmt.Errorf("launching keepalive instance from %v: %w: %v",
				imageID, ErrInstanceQuotaExceeded, strings.Join(attempts, "; "))
		}
		if !isUnusableInstanceTypeError(err) {
			break
		}
		plog.Debugf("keepalive instance type %v unusable in %v: %v", instanceType, a.opts.Region, err)
	}
	return "", "", fmt.Errorf("launching keepalive instance from %v: %v", imageID, strings.Join(attempts, "; "))
}

// runKeepaliveInstance makes one bounded RunInstances call. The client token
// makes it idempotent, so an SDK retry of a lost response returns the original
// launch rather than creating a second instance.
func (a *API) runKeepaliveInstance(imageID, instanceType string) (*ec2.RunInstancesOutput, error) {
	input := keepaliveRunInstancesInput(imageID, instanceType, uuid.NewString())
	ctx, cancel := context.WithTimeout(context.Background(), keepaliveRunTimeout)
	defer cancel()
	return a.ec2.RunInstances(ctx, &input)
}

func keepaliveRunInstancesInput(imageID, instanceType, clientToken string) ec2.RunInstancesInput {
	tags := []ec2types.Tag{
		{Key: aws.String("Name"), Value: aws.String(KeepalivePurpose + "-" + imageID)},
		{Key: aws.String("CreatedBy"), Value: aws.String("mantle")},
		{Key: aws.String("Purpose"), Value: aws.String(KeepalivePurpose)},
	}
	input := ec2.RunInstancesInput{
		ImageId:      aws.String(imageID),
		InstanceType: ec2types.InstanceType(instanceType),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		ClientToken:  aws.String(clientToken),
		TagSpecifications: []ec2types.TagSpecification{
			{ResourceType: ec2types.ResourceTypeInstance, Tags: tags},
			{ResourceType: ec2types.ResourceTypeVolume, Tags: tags},
		},
	}
	return input
}

// isUnusableInstanceTypeError reports whether another instance type might fix
// the failure: this one isn't offered here, isn't valid for the AMI, or is full.
func isUnusableInstanceTypeError(err error) bool {
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.ErrorCode() {
	case "Unsupported", "UnsupportedOperation", "InvalidInstanceType", "InsufficientInstanceCapacity":
		return true
	}
	return false
}

// isNoDefaultVPCError reports whether RunInstances failed for want of a default
// VPC. EC2 answers VPCIdNotSpecified when a request names no subnet and the
// region has no default; other calls report the same as DefaultVpcDoesNotExist.
func isNoDefaultVPCError(err error) bool {
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.ErrorCode() {
	case "VPCIdNotSpecified", "DefaultVpcDoesNotExist":
		return true
	}
	return false
}

// isInstanceQuotaError reports whether the account is at its on-demand instance
// limit for the region. Unlike a capacity shortfall this is a property of the
// account, not the moment, so retrying or switching type won't help until
// instances are released or the quota is raised.
func isInstanceQuotaError(err error) bool {
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.ErrorCode() {
	case "VcpuLimitExceeded", "InstanceLimitExceeded":
		return true
	}
	return false
}

// WaitForInstancesRunning waits for every given instance to reach "running" and
// returns the ones that didn't, keyed by instance ID, with EC2's reason where
// it gave one. A nil map means they all made it. The error is non-nil only when
// no state could be read at all, a different problem from a failed start.
func (a *API) WaitForInstancesRunning(ctx context.Context, ids []string, timeout time.Duration) (map[string]error, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	input := &ec2.DescribeInstancesInput{InstanceIds: ids}
	// The waiter already treats InvalidInstanceID.NotFound as "keep waiting",
	// covering an ID that isn't visible yet. Poll no faster, or risk throttling.
	waiter := ec2.NewInstanceRunningWaiter(a.ec2, func(o *ec2.InstanceRunningWaiterOptions) {
		o.MinDelay = 10 * time.Second
	})
	if err := waiter.Wait(ctx, input, timeout); err == nil {
		return nil, nil
	} else if ctx.Err() != nil {
		return nil, fmt.Errorf("waiting for instances to start: %v", err)
	}

	// The waiter only reports that something went wrong, so ask which.
	desc, err := a.ec2.DescribeInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("describing instances that failed to start: %v", err)
	}
	failures := map[string]error{}
	seen := map[string]bool{}
	for _, reservation := range desc.Reservations {
		for _, inst := range reservation.Instances {
			if inst.InstanceId == nil {
				continue
			}
			seen[*inst.InstanceId] = true
			var state ec2types.InstanceStateName
			if inst.State != nil {
				state = inst.State.Name
			}
			if state == ec2types.InstanceStateNameRunning {
				continue
			}
			failures[*inst.InstanceId] = fmt.Errorf("instance is %q: %s",
				string(state), instanceStateReason(inst))
		}
	}
	for _, id := range ids {
		if !seen[id] {
			failures[id] = errors.New("instance not found")
		}
	}
	return failures, nil
}

func instanceStateReason(inst ec2types.Instance) string {
	if inst.StateReason != nil && inst.StateReason.Message != nil {
		return *inst.StateReason.Message
	}
	return "no reason given"
}
