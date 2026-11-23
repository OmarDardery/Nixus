package main

import (
	"slices"
	"testing"
)

func TestComposeUpCommand(t *testing.T) {
	scratch := t.TempDir()
	image := M{"intentHash": "new", "services": []any{M{"service": "web", "built": false}}}
	args, _, err := composeUpCommand("incus-compose", []string{"-p", "x"}, image, "", scratch)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--no-build") || slices.Contains(args, "--build") || slices.Contains(args, "--recreate") {
		t.Fatalf("image-only first deploy: %v", args)
	}
	args, _, _ = composeUpCommand("incus-compose", nil, image, "old", scratch)
	if !slices.Contains(args, "--recreate") {
		t.Fatalf("a new revision must recreate instances: %v", args)
	}
	args, _, _ = composeUpCommand("incus-compose", nil, image, "new", scratch)
	if slices.Contains(args, "--recreate") {
		t.Fatalf("an unchanged revision must not recreate: %v", args)
	}
	built := M{"intentHash": "new", "services": []any{M{"service": "app", "built": true}}}
	t.Setenv("NIXUS_OCI_BUILDAH_BIN", "/nix/store/x-buildah/bin/buildah")
	args, env, err := composeUpCommand("incus-compose", nil, built, "", scratch)
	if err != nil || !slices.Contains(args, "--build") || slices.Contains(args, "--no-build") ||
		args[slices.Index(args, "--builder")+1] != "/nix/store/x-buildah/bin/buildah" || !slices.Contains(env, "BUILDAH_ISOLATION=chroot") {
		t.Fatalf("built service: %v %v %v", args, env, err)
	}
}
