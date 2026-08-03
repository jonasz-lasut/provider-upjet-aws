// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: CC0-1.0

package common

import (
	"context"
	"testing"
	"time"

	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource/fake"
	"github.com/crossplane/crossplane-runtime/v2/pkg/test"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ujfake "github.com/crossplane/upjet/v2/pkg/resource/fake"
)

var (
	errBoom = errors.New("boom")
)

func TestPasswordGenerator(t *testing.T) {
	type args struct {
		kube               client.Client
		secretRefFieldPath string
		toggleFieldPath    string
		mg                 resource.Managed
	}
	type want struct {
		err error
	}
	cases := map[string]struct {
		reason string
		args   args
		want   want
	}{
		"CannotGetSecret": {
			reason: "An error should be returned if the referenced secret cannot be retrieved.",
			args: args{
				kube: &test.MockClient{
					MockGet: test.NewMockGetFn(errBoom),
				},
				secretRefFieldPath: "",
				toggleFieldPath:    "",
				mg: &fake.Managed{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo-mgd",
						Namespace: "bar",
					},
				},
			},
			want: want{
				err: errors.Wrap(errBoom, ErrGetPasswordSecret),
			},
		},
		"ClusterScopedMR": {
			reason: "should return an error if the MR has no namespace (cluster-scoped)",
			args: args{
				kube: &test.MockClient{
					MockGet: func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						s.Data = map[string][]byte{
							"password": []byte("foo"),
						}
						return nil
					},
				},
				secretRefFieldPath: "parameterizable.parameters.passwordSecretRef",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo-mgd",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"passwordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
						},
					},
				},
			},
			want: want{
				err: errors.New(errManagedNotNamespaced),
			},
		},
		"SecretAlreadyFull": {
			reason: "Should be no-op if the Secret already has password.",
			args: args{
				kube: &test.MockClient{
					MockGet: func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						s.Data = map[string][]byte{
							"password": []byte("foo"),
						}
						return nil
					},
				},
				secretRefFieldPath: "parameterizable.parameters.passwordSecretRef",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"passwordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
						},
					},
				},
			},
		},
		"ClusterSecretAlreadyFull": {
			reason: "Should be no-op if the Secret already has password.",
			args: args{
				kube: &test.MockClient{
					MockGet: func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						s.Data = map[string][]byte{
							"password": []byte("foo"),
						}
						return nil
					},
				},
				secretRefFieldPath: "parameterizable.parameters.masterPasswordSecretRef",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"masterPasswordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
						},
					},
				},
			},
		},
		"NoSecretReference": {
			reason: "Should be no-op if the secret reference is not given.",
			args: args{
				secretRefFieldPath: "parameterizable.parameters.passwordSecretRef",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"another": "field",
						},
					},
				},
			},
		},
		"NoClusterSecretReference": {
			reason: "Should be no-op if the secret reference is not given.",
			args: args{
				secretRefFieldPath: "parameterizable.parameters.masterPasswordSecretRef",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"another": "field",
						},
					},
				},
			},
		},
		"ToggleNotSet": {
			reason: "Should be no-op if the toggle is not set at all.",
			args: args{
				kube: &test.MockClient{
					MockGet: test.NewMockGetFn(nil),
				},
				secretRefFieldPath: "parameterizable.parameters.passwordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"passwordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
						},
					},
				},
			},
		},
		"ClusterToggleNotSet": {
			reason: "Should be no-op if the toggle is not set at all.",
			args: args{
				kube: &test.MockClient{
					MockGet: test.NewMockGetFn(nil),
				},
				secretRefFieldPath: "parameterizable.parameters.masterPasswordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"masterPasswordSecretRef": map[string]any{
								"name":      "foo",
								"namespace": "bar",
								"key":       "password",
							},
						},
					},
				},
			},
		},
		"ToggleFalse": {
			reason: "Should be no-op if the toggle is set to false.",
			args: args{
				kube: &test.MockClient{
					MockGet: test.NewMockGetFn(nil),
				},
				secretRefFieldPath: "parameterizable.parameters.passwordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"passwordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
							"autoGeneratePassword": false,
						},
					},
				},
			},
		},
		"ClusterToggleFalse": {
			reason: "Should be no-op if the toggle is set to false.",
			args: args{
				kube: &test.MockClient{
					MockGet: test.NewMockGetFn(nil),
				},
				secretRefFieldPath: "parameterizable.parameters.masterPasswordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"masterPasswordSecretRef": map[string]any{
								"name":      "foo",
								"namespace": "bar",
								"key":       "password",
							},
							"autoGeneratePassword": false,
						},
					},
				},
			},
		},
		"GenerateAndApply": {
			reason: "Should apply if we generate, set the content of an already existing secret.",
			args: args{
				kube: &test.MockClient{
					MockGet: func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						s.CreationTimestamp = metav1.Time{Time: time.Now()}
						return nil
					},
					MockPatch: func(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						if len(s.Data["password"]) == 0 {
							return errors.New("password is not set")
						}
						if len(s.OwnerReferences) != 0 {
							return errors.New("owner references should not be set if secret already exists")
						}
						return nil
					},
				},
				secretRefFieldPath: "parameterizable.parameters.passwordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"passwordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
							"autoGeneratePassword": true,
						},
					},
				},
			},
		},
		"ClusterSecretGenerateAndApply": {
			reason: "Should apply if we generate, set the content of an already existing secret.",
			args: args{
				kube: &test.MockClient{
					MockGet: func(ctx context.Context, key client.ObjectKey, obj client.Object) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						s.CreationTimestamp = metav1.Time{Time: time.Now()}
						return nil
					},
					MockPatch: func(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						if len(s.Data["password"]) == 0 {
							return errors.New("password is not set")
						}
						if len(s.OwnerReferences) != 0 {
							return errors.New("owner references should not be set if secret already exists")
						}
						return nil
					},
				},
				secretRefFieldPath: "parameterizable.parameters.masterPasswordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"masterPasswordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
							"autoGeneratePassword": true,
						},
					},
				},
			},
		},
		"GenerateAndCreate": {
			reason: "Should create if we generate, set the content and there is no secret in place.",
			args: args{
				kube: &test.MockClient{
					MockGet: test.NewMockGetFn(kerrors.NewNotFound(schema.GroupResource{}, "")),
					MockCreate: func(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						if len(s.Data["password"]) == 0 {
							return errors.New("password is not set")
						}
						if len(s.OwnerReferences) == 1 &&
							s.OwnerReferences[0].Name == "foo-mgd" {
							return nil
						}
						return errors.New("owner references should be set if secret is created")
					},
				},
				secretRefFieldPath: "parameterizable.parameters.passwordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"passwordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
							"autoGeneratePassword": true,
						},
					},
				},
			},
		},
		"ClusterSecretGenerateAndCreate": {
			reason: "Should create if we generate, set the content and there is no secret in place.",
			args: args{
				kube: &test.MockClient{
					MockGet: test.NewMockGetFn(kerrors.NewNotFound(schema.GroupResource{}, "")),
					MockCreate: func(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
						s, ok := obj.(*corev1.Secret)
						if !ok {
							return errors.New("needs to be secret")
						}
						if len(s.Data["password"]) == 0 {
							return errors.New("password is not set")
						}
						if len(s.OwnerReferences) == 1 &&
							s.OwnerReferences[0].Name == "foo-mgd" {
							return nil
						}
						return errors.New("owner references should be set if secret is created")
					},
				},
				secretRefFieldPath: "parameterizable.parameters.masterPasswordSecretRef",
				toggleFieldPath:    "parameterizable.parameters.autoGeneratePassword",
				mg: &ujfake.Terraformed{
					Managed: fake.Managed{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-mgd",
							Namespace: "bar",
						},
					},
					Parameterizable: ujfake.Parameterizable{
						Parameters: map[string]any{
							"masterPasswordSecretRef": map[string]any{
								"name": "foo",
								"key":  "password",
							},
							"autoGeneratePassword": true,
						},
					},
				},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := PasswordGenerator(tc.args.secretRefFieldPath, tc.args.toggleFieldPath)(tc.args.kube).Initialize(context.Background(), tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("PasswordGenerator(...): -want error, +got error:\n%s", diff)
			}
		})
	}

}

func TestRemoveApplyMethodOnlyParameterDiffs(t *testing.T) {
	elem := func(hash, name, value, applyMethod string, removed bool) map[string]*terraform.ResourceAttrDiff {
		m := map[string]*terraform.ResourceAttrDiff{}
		for field, val := range map[string]string{"name": name, "value": value, "apply_method": applyMethod} {
			if removed {
				m["parameter."+hash+"."+field] = &terraform.ResourceAttrDiff{Old: val, NewRemoved: true}
			} else {
				m["parameter."+hash+"."+field] = &terraform.ResourceAttrDiff{New: val}
			}
		}
		return m
	}
	merge := func(ms ...map[string]*terraform.ResourceAttrDiff) map[string]*terraform.ResourceAttrDiff {
		out := map[string]*terraform.ResourceAttrDiff{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	state := &terraform.InstanceState{ID: "example"}

	type args struct {
		diff  *terraform.InstanceDiff
		state *terraform.InstanceState
	}
	type want struct {
		attributes map[string]*terraform.ResourceAttrDiff
	}
	cases := map[string]struct {
		reason string
		args   args
		want   want
	}{
		"ApplyMethodOnlyDiffRemoved": {
			reason: "A parameter whose only change is apply_method must not produce a diff, including the no-op element count.",
			args: args{
				diff: &terraform.InstanceDiff{Attributes: merge(
					elem("111", "rds.force_ssl", "1", "pending-reboot", true),
					elem("222", "rds.force_ssl", "1", "immediate", false),
					map[string]*terraform.ResourceAttrDiff{"parameter.#": {Old: "1", New: "1"}},
				)},
				state: state,
			},
			want: want{attributes: map[string]*terraform.ResourceAttrDiff{}},
		},
		"ValueChangeKept": {
			reason: "A parameter whose value changes must keep its full diff so apply_method is honored on the update.",
			args: args{
				diff: &terraform.InstanceDiff{Attributes: merge(
					elem("111", "rds.force_ssl", "1", "pending-reboot", true),
					elem("222", "rds.force_ssl", "0", "immediate", false),
				)},
				state: state,
			},
			want: want{attributes: merge(
				elem("111", "rds.force_ssl", "1", "pending-reboot", true),
				elem("222", "rds.force_ssl", "0", "immediate", false),
			)},
		},
		"MixedSetOnlyNoOpPairRemoved": {
			reason: "Only the apply_method-only pair is removed; a genuine value change and the element count are kept.",
			args: args{
				diff: &terraform.InstanceDiff{Attributes: merge(
					elem("111", "rds.force_ssl", "1", "pending-reboot", true),
					elem("222", "rds.force_ssl", "1", "immediate", false),
					elem("333", "log_checkpoints", "1", "pending-reboot", true),
					elem("444", "log_checkpoints", "0", "immediate", false),
					map[string]*terraform.ResourceAttrDiff{"parameter.#": {Old: "2", New: "2"}},
				)},
				state: state,
			},
			want: want{attributes: merge(
				elem("333", "log_checkpoints", "1", "pending-reboot", true),
				elem("444", "log_checkpoints", "0", "immediate", false),
				map[string]*terraform.ResourceAttrDiff{"parameter.#": {Old: "2", New: "2"}},
			)},
		},
		"AddedParameterKept": {
			reason: "A newly added parameter with no removed counterpart must keep its diff.",
			args: args{
				diff: &terraform.InstanceDiff{Attributes: merge(
					elem("222", "rds.force_ssl", "1", "immediate", false),
					map[string]*terraform.ResourceAttrDiff{"parameter.#": {Old: "0", New: "1"}},
				)},
				state: state,
			},
			want: want{attributes: merge(
				elem("222", "rds.force_ssl", "1", "immediate", false),
				map[string]*terraform.ResourceAttrDiff{"parameter.#": {Old: "0", New: "1"}},
			)},
		},
		"SameApplyMethodDifferentCaseKept": {
			reason: "A pair equal in value and case-insensitively equal in apply_method is not the apply_method bug and is left untouched.",
			args: args{
				diff: &terraform.InstanceDiff{Attributes: merge(
					elem("111", "rds.force_ssl", "1", "immediate", true),
					elem("222", "rds.force_ssl", "1", "IMMEDIATE", false),
				)},
				state: state,
			},
			want: want{attributes: merge(
				elem("111", "rds.force_ssl", "1", "immediate", true),
				elem("222", "rds.force_ssl", "1", "IMMEDIATE", false),
			)},
		},
		"NonParameterDiffUntouched": {
			reason: "Diffs outside the parameter set are never touched.",
			args: args{
				diff: &terraform.InstanceDiff{Attributes: merge(
					elem("111", "ttl_monitor", "enabled", "pending-reboot", true),
					elem("222", "ttl_monitor", "enabled", "immediate", false),
					map[string]*terraform.ResourceAttrDiff{"tags.foo": {Old: "a", New: "b"}},
				)},
				state: state,
			},
			want: want{attributes: map[string]*terraform.ResourceAttrDiff{"tags.foo": {Old: "a", New: "b"}}},
		},
		"CreateSkipped": {
			reason: "With no state the resource is being created and the diff is returned unmodified.",
			args: args{
				diff: &terraform.InstanceDiff{Attributes: merge(
					elem("222", "rds.force_ssl", "1", "immediate", false),
				)},
				state: nil,
			},
			want: want{attributes: merge(
				elem("222", "rds.force_ssl", "1", "immediate", false),
			)},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := RemoveApplyMethodOnlyParameterDiffs(tc.args.diff, tc.args.state, nil)
			if err != nil {
				t.Fatalf("\n%s\nRemoveApplyMethodOnlyParameterDiffs(...): unexpected error: %v", tc.reason, err)
			}
			if diff := cmp.Diff(tc.want.attributes, got.Attributes); diff != "" {
				t.Errorf("\n%s\nRemoveApplyMethodOnlyParameterDiffs(...): -want attributes, +got attributes:\n%s", tc.reason, diff)
			}
		})
	}
}
