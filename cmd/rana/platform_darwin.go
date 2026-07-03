//go:build darwin

package main

import (
	"fmt"
	"io"
	"runtime"
)

// runPlatform (macOS) explains that recording on macOS means running the
// agent inside RanA's Linux guest — there is no native macOS capture path
// (Endpoint Security entitlements are closed to OSS; plan D2/D15). This build
// wires the CLI surface; booting the guest requires the guest image and the
// `com.apple.security.virtualization` entitlement (see docs/MACOS.md and
// `rana vm`). RanA never pretends to record a native macOS process.
func runPlatform(p runParams) int {
	fmt.Fprintln(p.Stderr, "rana run: on macOS, agents are recorded inside RanA's Linux guest VM.")
	fmt.Fprintln(p.Stderr, "A native macOS process produces zero kernel events and is not recorded.")
	fmt.Fprintln(p.Stderr, "")
	fmt.Fprintln(p.Stderr, "Set up the guest first:  rana vm start")
	fmt.Fprintln(p.Stderr, "Then:                    rana run --profile "+p.Profile.Name+" -- "+firstOr(p.Command, "<cmd>"))
	fmt.Fprintln(p.Stderr, "See docs/MACOS.md for the guest image and entitlement requirements.")
	return exitUsage
}

// adoptPlatform (macOS) explains the guest-hosted adopt path: the Linux build
// of the gateway runs on the guest data volume, config is projected via
// virtiofs, and :18789 is port-forwarded to host localhost. There is no
// degraded native mode (plan D18).
func adoptPlatform(p adoptParams) int {
	fmt.Fprintf(p.Stdout, "rana adopt %s (macOS): the gateway is hosted inside RanA's Linux guest.\n", p.Target)
	if p.Profile.Adopt != nil && p.Profile.Adopt.GatewayPort != 0 {
		fmt.Fprintf(p.Stdout, "  config:       %s (projected via virtiofs)\n", p.Profile.Adopt.ConfigDir)
		fmt.Fprintf(p.Stdout, "  gateway port: %d (forwarded to host 127.0.0.1)\n", p.Profile.Adopt.GatewayPort)
	}
	fmt.Fprintln(p.Stdout, "A native macOS gateway cannot be recorded (no ES entitlement path).")
	fmt.Fprintln(p.Stdout, "Start the guest first with `rana vm start`; see docs/MACOS.md and docs/OPENCLAW.md.")
	return exitOK
}

// cmdVM manages the macOS Linux guest. Booting a real guest needs the guest
// image and the virtualization entitlement (a signed binary); this build
// reports guest status and guides setup honestly rather than pretending to
// boot an image that isn't present.
func cmdVM(args []string, stdout, stderr io.Writer) int {
	sub := "status"
	if len(args) >= 1 {
		sub = args[0]
	}
	switch sub {
	case "status":
		fmt.Fprintf(stdout, "rana vm: macOS %s guest support\n", runtime.GOARCH)
		fmt.Fprintln(stdout, "  guest image: not installed (see docs/MACOS.md to build/fetch it)")
		if runtime.GOARCH != "arm64" {
			fmt.Fprintln(stdout, "  note: warm-pool save/restore is Apple-Silicon only (Intel is cold-boot only)")
		}
		return exitOK
	case "start", "stop", "reset":
		fmt.Fprintf(stdout, "rana vm %s: requires the guest image and a signed binary with the\n", sub)
		fmt.Fprintln(stdout, "  com.apple.security.virtualization entitlement. See docs/MACOS.md.")
		return exitOK
	default:
		fmt.Fprintf(stderr, "rana vm: unknown subcommand %q (want: status|start|stop|reset)\n", sub)
		return exitUsage
	}
}

// doctorPlatform (macOS) reports the guest-based recording model.
func doctorPlatform(w io.Writer) {
	fmt.Fprintf(w, "Platform: macOS/%s (records inside a Linux guest VM)\n", runtime.GOARCH)
	if runtime.GOARCH == "arm64" {
		fmt.Fprintln(w, "  virtualization: Apple Silicon (warm-pool save/restore supported on macOS 14+)")
	} else {
		fmt.Fprintln(w, "  virtualization: Intel best-effort (cold boot only; no warm pool)")
	}
	fmt.Fprintln(w, "  native macOS processes are NOT recorded (docs/MACOS.md, LIMITS.md §5)")
	fmt.Fprintln(w, "")
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}
