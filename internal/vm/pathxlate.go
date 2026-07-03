// Package vm implements RanA's macOS microVM lifecycle: guest boot/stop via
// Apple's Virtualization.framework (Code-Hex/vz), virtiofs path projection,
// vsock control/data plane, and vsock<->TCP port-forwarding for adopted
// services (CONTRACTS §internal/vm, docs/MACOS.md, docs/ARCHITECTURE.md
// §6.2).
//
// Everything in this package that does not directly drive vz is kept
// portable (buildable and testable on darwin and linux both): path
// translation between the guest's /mnt/host/<tag> virtiofs mounts and real
// host paths, the vsock<->TCP port-forward proxy (built over an injected
// dialer, not a real vsock connection), the layered guest-image resolver,
// and guest configuration assembly. Only the code that calls into
// Code-Hex/vz itself lives behind `//go:build darwin && cgo`
// (CLAUDE.md §3.2, CONTRACTS cross-platform discipline).
package vm

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// guestMountBase is the fixed parent directory under which every virtiofs
// projection is mounted inside the guest, one subdirectory per tag
// (docs/ARCHITECTURE.md §6.2: "mounted read-write at /mnt/host/<name> in
// guest"; docs/MACOS.md §1).
const guestMountBase = "/mnt/host"

// Mount describes one granted host directory projected into the guest as a
// virtiofs tag, mounted at /mnt/host/<Tag> (docs/MACOS.md §1
// "Projections").
type Mount struct {
	// Tag is the virtiofs device tag and the guest-side mount directory
	// name under /mnt/host/. It must be non-empty and must not contain
	// '/' (it is a single path segment, not a path).
	Tag string

	// HostRoot is the absolute host directory this tag projects. It must
	// be an absolute path (host-OS-native; on darwin this is the real
	// filesystem path granted to the session).
	HostRoot string
}

// ErrDuplicateTag is returned by NewPathXlate when two Mounts share the
// same Tag.
var ErrDuplicateTag = errors.New("vm: duplicate virtiofs tag")

// ErrInvalidMount is returned by NewPathXlate when a Mount has an empty
// Tag, a Tag containing '/', or a HostRoot that is empty or not absolute.
var ErrInvalidMount = errors.New("vm: invalid mount")

// ErrPathNotMapped is returned by GuestToHost and HostToGuest when the
// given path does not fall under any configured mount.
var ErrPathNotMapped = errors.New("vm: path not mapped by any mount")

// PathXlate translates paths between the guest's /mnt/host/<tag> virtiofs
// namespace and real host paths, using longest-prefix match over the
// configured Mounts (CONTRACTS §internal/vm: "PathXlate (host<->/mnt/host/
// <tag> mount table, longest-prefix match, ROUND-TRIP + traversal-safety
// tests)").
//
// PathXlate is immutable after construction and safe for concurrent use by
// multiple goroutines (it holds no mutable shared state past NewPathXlate).
type PathXlate struct {
	// byTag is keyed by tag name for guest->host lookup.
	byTag map[string]string // tag -> cleaned absolute host root, no trailing slash

	// byHostRoot is sorted by HostRoot length descending, so the first
	// matching entry in a linear scan is always the longest (most
	// specific) prefix match, implementing "longest-prefix match" for
	// host->guest translation without requiring a trie.
	byHostRoot []hostEntry
}

type hostEntry struct {
	tag      string
	hostRoot string // cleaned absolute path, no trailing slash
}

// NewPathXlate validates mounts and builds a PathXlate ready to translate
// paths in both directions. It rejects duplicate tags and structurally
// invalid mounts (ErrInvalidMount, ErrDuplicateTag) — this validation, plus
// the traversal-safe implementation of GuestToHost, is what makes it
// impossible for a mount table entry (however configured) to let a guest
// path escape its own tag root.
func NewPathXlate(mounts []Mount) (*PathXlate, error) {
	byTag := make(map[string]string, len(mounts))
	byHostRoot := make([]hostEntry, 0, len(mounts))

	for _, m := range mounts {
		if m.Tag == "" || strings.ContainsRune(m.Tag, '/') {
			return nil, fmt.Errorf("%w: tag %q", ErrInvalidMount, m.Tag)
		}
		if m.HostRoot == "" || !path.IsAbs(m.HostRoot) {
			return nil, fmt.Errorf("%w: host root %q for tag %q must be an absolute path", ErrInvalidMount, m.HostRoot, m.Tag)
		}
		if _, exists := byTag[m.Tag]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateTag, m.Tag)
		}

		cleanRoot := strings.TrimSuffix(path.Clean(m.HostRoot), "/")
		if cleanRoot == "" {
			cleanRoot = "/"
		}

		byTag[m.Tag] = cleanRoot
		byHostRoot = append(byHostRoot, hostEntry{tag: m.Tag, hostRoot: cleanRoot})
	}

	// Sort by hostRoot length descending so HostToGuest's linear scan
	// finds the longest (most specific) matching root first.
	sort.Slice(byHostRoot, func(i, j int) bool {
		return len(byHostRoot[i].hostRoot) > len(byHostRoot[j].hostRoot)
	})

	return &PathXlate{byTag: byTag, byHostRoot: byHostRoot}, nil
}

// GuestToHost translates a guest-side path under /mnt/host/<tag> to the
// corresponding host path.
//
// Traversal safety: the guest path is cleaned (path.Clean, resolving any
// "." and ".." segments) before the tag is extracted, and the segment
// immediately following /mnt/host/ is taken as the literal tag name — it
// cannot itself be traversed away from, because path.Clean collapses ".."
// only against segments that already exist earlier in the same path
// string, and any residual ".." that would walk above the tag root is
// preserved as a literal leading ".." in the remainder, which is then
// rejected outright (see below) rather than joined onto the host root.
// This guarantees a guest path can never translate to a host path outside
// its tag's HostRoot (CONTRACTS: "test ../ escapes").
func (px *PathXlate) GuestToHost(guestPath string) (string, error) {
	clean := path.Clean(guestPath)
	rest, ok := stripPrefixSegments(clean, guestMountBase)
	if !ok {
		return "", fmt.Errorf("%w: %q is not under %s", ErrPathNotMapped, guestPath, guestMountBase)
	}

	tag, remainder, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	if tag == "" {
		return "", fmt.Errorf("%w: %q has no tag segment", ErrPathNotMapped, guestPath)
	}

	hostRoot, ok := px.byTag[tag]
	if !ok {
		return "", fmt.Errorf("%w: unknown tag %q in %q", ErrPathNotMapped, tag, guestPath)
	}

	if remainder == "" {
		return hostRoot, nil
	}

	// remainder came from path.Clean's output, so it cannot start with
	// "../" while also being a strict sub-path unless the original guest
	// path attempted to walk above the tag root — reject that outright
	// rather than joining it (which path.Join would otherwise silently
	// collapse onto a path outside hostRoot).
	if remainder == ".." || strings.HasPrefix(remainder, "../") {
		return "", fmt.Errorf("%w: %q escapes tag root %q", ErrPathNotMapped, guestPath, tag)
	}

	return hostRoot + "/" + remainder, nil
}

// HostToGuest translates a host path to its guest-side /mnt/host/<tag>
// path, choosing the longest (most specific) matching Mount when multiple
// configured roots are prefixes of the given path.
func (px *PathXlate) HostToGuest(hostPath string) (string, error) {
	clean := strings.TrimSuffix(path.Clean(hostPath), "/")
	if clean == "" {
		clean = "/"
	}

	for _, e := range px.byHostRoot {
		if clean == e.hostRoot {
			return guestMountBase + "/" + e.tag, nil
		}
		if strings.HasPrefix(clean, e.hostRoot+"/") {
			remainder := clean[len(e.hostRoot)+1:]
			return guestMountBase + "/" + e.tag + "/" + remainder, nil
		}
	}

	return "", fmt.Errorf("%w: %q is not under any configured host root", ErrPathNotMapped, hostPath)
}

// Mounts returns a sorted (by Tag), independent copy of the configured
// mounts. Callers may freely mutate the returned slice.
func (px *PathXlate) Mounts() []Mount {
	out := make([]Mount, 0, len(px.byTag))
	for tag, root := range px.byTag {
		out = append(out, Mount{Tag: tag, HostRoot: root})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

// stripPrefixSegments reports whether p (already path.Clean'd) is equal to
// prefix or has prefix as a leading sequence of path segments, returning
// the remainder starting with "/" (or "" if p == prefix exactly).
func stripPrefixSegments(p, prefix string) (rest string, ok bool) {
	if p == prefix {
		return "", true
	}
	if strings.HasPrefix(p, prefix+"/") {
		return p[len(prefix):], true
	}
	return "", false
}
