package scan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
	"github.com/darkLabz001/php2shell-audit/internal/phpver"
)

var containerIDRE = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// Docker inventories running containers that expose a PHP runtime. It uses
// the local docker CLI, so it only works where the socket is reachable.
func Docker(ctx context.Context, timeout time.Duration) *Result {
	res := &Result{}
	out, err := runCmd(ctx, timeout, "docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Ports}}")
	if err != nil {
		res.warn("docker inventory skipped: %v", err)
		return res
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 4)
		if len(parts) < 3 || parts[0] == "" {
			continue
		}
		id, image, name := parts[0], parts[1], parts[2]
		if !containerIDRE.MatchString(id) || seen[id] {
			continue
		}
		seen[id] = true

		target := fmt.Sprintf("container: %s (%s)", name, image)
		ver, sapi, cfg, notes := inspectContainer(ctx, id, timeout)
		t := model.Target{
			Name: target, Kind: "container", Image: image, Source: id,
			Config: cfg, Notes: notes,
		}
		if ver == nil {
			t.Status = phpver.StatusUnknown
			res.addTarget(t)
			res.add(model.Finding{
				ID: "P2S-CTR-001", Target: target, Surface: "container",
				Title: "Container runs PHP but the version could not be read", Severity: model.Medium,
				Category: "exposure", Confidence: "low", Status: phpver.StatusUnknown,
				Detail:      "The container did not answer a php -r probe. It may not contain PHP, may be distroless, or may be too locked down for docker exec.",
				Evidence:    []string{"image: " + image, "container: " + id[:12]},
				Remediation: "Rebuild the image on a patched base or run the probe inside the container manually.",
			})
			continue
		}
		a := phpver.Assess(*ver)
		t.Version = ver.Raw
		t.Status = a.Status
		t.FixedIn = a.FixedIn
		t.SAPI = sapi
		res.addTarget(t)
		res.add(ExposureFinding(target, "container", sapi, ver.Raw, a, "docker exec"))

		// Base images are usually pinned by tag. A floating tag makes patch
		// verification impossible after the fact.
		if imageTagIsFloating(image) {
			res.add(model.Finding{
				ID: "P2S-CTR-002", Target: target, Surface: "container",
				Title: "Container image uses a floating tag", Severity: model.Low,
				Category: "config", Confidence: "high",
				Evidence:    []string{"image: " + image},
				Detail:      "A floating tag (latest, edge, or no tag) cannot prove which PHP build is deployed. Pin the digest so the patched image can be verified.",
				Remediation: "Pin the image by digest and rebuild after the PHP base image is patched.",
			})
		}
	}
	return res
}

const containerProbe = `if command -v php >/dev/null 2>&1; then php -r 'echo "ver\t",PHP_VERSION,"\n";echo "sapi\t",PHP_SAPI,"\n";echo "mem\t",ini_get("memory_limit"),"\n";echo "post\t",ini_get("post_max_size"),"\n";echo "prog\t",ini_get("session.upload_progress.enabled"),"\n";echo "back\t",ini_get("fatal_error_backtraces"),"\n";'; fi`

func inspectContainer(ctx context.Context, id string, timeout time.Duration) (*phpver.Version, string, map[string]string, []string) {
	out, err := runCmd(ctx, timeout, "docker", "exec", id, "sh", "-c", containerProbe)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, "", nil, []string{"probe failed: " + err.Error()}
	}
	var ver *phpver.Version
	sapi := ""
	cfg := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "ver":
			if v, ok := phpver.Parse(parts[1]); ok {
				ver = &v
			}
		case "sapi":
			sapi = parts[1]
		case "mem":
			cfg["memory_limit"] = parts[1]
		case "post":
			cfg["post_max_size"] = parts[1]
		case "prog":
			cfg["session.upload_progress.enabled"] = parts[1]
		case "back":
			cfg["fatal_error_backtraces"] = parts[1]
		}
	}
	return ver, sapi, cfg, nil
}

func imageTagIsFloating(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	i := strings.LastIndex(image, ":")
	if i < 0 || strings.Contains(image[i:], "/") {
		return true
	}
	tag := image[i+1:]
	return tag == "latest" || tag == "edge" || tag == "dev" || tag == "stable"
}
