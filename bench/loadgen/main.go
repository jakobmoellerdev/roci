// Command loadgen seeds a deterministic many-tag OCI corpus into a registry
// using the same 7-request push flow a real client uses, and reports
// throughput/latency. Stdlib only; content is identical across registries.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	mtManifest = "application/vnd.oci.image.manifest.v1+json"
	mtConfig   = "application/vnd.oci.image.config.v1+json"
	mtLayer    = "application/vnd.oci.image.layer.v1.tar"
)

type rootfs struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}
type imgCfgInner struct {
	Labels map[string]string `json:"Labels"`
}
type imgConfig struct {
	Architecture string      `json:"architecture"`
	OS           string      `json:"os"`
	RootFS       rootfs      `json:"rootfs"`
	Config       imgCfgInner `json:"config"`
}
type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}
type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type image struct {
	Repo           string `json:"repo"`
	Tag            string `json:"tag"`
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
	LayerDigest    string `json:"layer_digest"`
	layer, config  []byte
	manifest       []byte
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func build(seed, i, j int) image {
	repo := fmt.Sprintf("bench/corpus-%03d", i)
	tag := fmt.Sprintf("t%04d", j)
	key := sha256.Sum256([]byte(fmt.Sprintf("%d/%d/%d", seed, i, j)))
	layer := make([]byte, 4096)
	_, _ = rand.NewChaCha8(key).Read(layer)
	ld := digest(layer)
	cfg, _ := json.Marshal(imgConfig{
		Architecture: "amd64", OS: "linux",
		RootFS: rootfs{Type: "layers", DiffIDs: []string{ld}},
		Config: imgCfgInner{Labels: map[string]string{"bench.repo": repo, "bench.tag": tag}},
	})
	cd := digest(cfg)
	man, _ := json.Marshal(manifest{
		SchemaVersion: 2, MediaType: mtManifest,
		Config: descriptor{MediaType: mtConfig, Digest: cd, Size: len(cfg)},
		Layers: []descriptor{{MediaType: mtLayer, Digest: ld, Size: len(layer)}},
	})
	return image{Repo: repo, Tag: tag, ManifestDigest: digest(man), ConfigDigest: cd, LayerDigest: ld,
		layer: layer, config: cfg, manifest: man}
}

type pusher struct {
	base   *url.URL
	client *http.Client
}

func (p *pusher) do(method, u string, body []byte, ctype string, want ...int) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %v", method, pathOf(u), err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	for _, w := range want {
		if resp.StatusCode == w {
			return resp, nil
		}
	}
	return resp, fmt.Errorf("%s %s: %d", method, pathOf(u), resp.StatusCode)
}

func pathOf(u string) string {
	if pu, err := url.Parse(u); err == nil {
		return pu.Path
	}
	return u
}

func (p *pusher) blob(repo, d string, b []byte) error {
	resp, err := p.do(http.MethodHead, p.base.String()+"/v2/"+repo+"/blobs/"+d, nil, "", 200, 404)
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		return nil
	}
	resp, err = p.do(http.MethodPost, p.base.String()+"/v2/"+repo+"/blobs/uploads/", nil, "", 202)
	if err != nil {
		return err
	}
	loc, err := p.base.Parse(resp.Header.Get("Location"))
	if err != nil || resp.Header.Get("Location") == "" {
		return fmt.Errorf("POST /v2/%s/blobs/uploads/: bad Location %q", repo, resp.Header.Get("Location"))
	}
	u := loc.String()
	if strings.Contains(u, "?") {
		u += "&digest=" + url.QueryEscape(d)
	} else {
		u += "?digest=" + url.QueryEscape(d)
	}
	_, err = p.do(http.MethodPut, u, b, "application/octet-stream", 201)
	return err
}

func (p *pusher) push(im image) error {
	if err := p.blob(im.Repo, im.LayerDigest, im.layer); err != nil {
		return err
	}
	if err := p.blob(im.Repo, im.ConfigDigest, im.config); err != nil {
		return err
	}
	_, err := p.do(http.MethodPut, p.base.String()+"/v2/"+im.Repo+"/manifests/"+im.Tag, im.manifest, mtManifest, 201)
	return err
}

func (p *pusher) verify(im image) error {
	req, _ := http.NewRequest(http.MethodGet, p.base.String()+"/v2/"+im.Repo+"/manifests/"+im.Tag, nil)
	req.Header.Set("Accept", mtManifest)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("verify GET %s:%s: %v", im.Repo, im.Tag, err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("verify GET /v2/%s/manifests/%s: %d", im.Repo, im.Tag, resp.StatusCode)
	}
	if digest(b) != im.ManifestDigest {
		return fmt.Errorf("verify %s:%s: digest mismatch %s != %s", im.Repo, im.Tag, digest(b), im.ManifestDigest)
	}
	return nil
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	k := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if k < 0 {
		k = 0
	}
	return sorted[k]
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "seed" {
		fmt.Fprintln(os.Stderr, "usage: loadgen seed -registry URL -repos N -tags M -seed S -concurrency C -corpus OUT.json -stats OUT.json")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	reg := fs.String("registry", "", "registry base URL")
	repos := fs.Int("repos", 10, "repositories")
	tags := fs.Int("tags", 50, "tags per repository")
	seed := fs.Int("seed", 42, "content seed")
	conc := fs.Int("concurrency", 16, "workers")
	corpusOut := fs.String("corpus", "corpus.json", "corpus output")
	statsOut := fs.String("stats", "stats.json", "stats output")
	_ = fs.Parse(os.Args[2:])
	base, err := url.Parse(strings.TrimRight(*reg, "/"))
	if err != nil || base.Host == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -registry must be an absolute URL")
		os.Exit(2)
	}
	p := &pusher{base: base, client: &http.Client{
		Transport: &http.Transport{MaxIdleConnsPerHost: *conc, DisableCompression: true},
		Timeout:   60 * time.Second,
	}}

	images := make([]image, 0, *repos**tags)
	repoNames := make([]string, 0, *repos)
	for i := 0; i < *repos; i++ {
		for j := 0; j < *tags; j++ {
			images = append(images, build(*seed, i, j))
		}
		repoNames = append(repoNames, fmt.Sprintf("bench/corpus-%03d", i))
	}

	var (
		mu     sync.Mutex
		errs   []string
		nerr   int
		lat    = make([]float64, 0, len(images))
		wg     sync.WaitGroup
		jobs   = make(chan int)
		addErr = func(e error) {
			mu.Lock()
			nerr++
			if len(errs) < 10 {
				errs = append(errs, e.Error())
			}
			mu.Unlock()
		}
	)
	start := time.Now()
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range jobs {
				t0 := time.Now()
				if err := p.push(images[k]); err != nil {
					addErr(err)
					continue
				}
				d := float64(time.Since(t0).Microseconds()) / 1000
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}()
	}
	for k := range images {
		jobs <- k
	}
	close(jobs)
	wg.Wait()
	dur := time.Since(start).Seconds()

	for k := 0; k < len(images); k += 100 {
		if err := p.verify(images[k]); err != nil {
			addErr(err)
		}
	}

	sort.Float64s(lat)
	maxLat := 0.0
	if len(lat) > 0 {
		maxLat = lat[len(lat)-1]
	}
	writeJSON(*corpusOut, map[string]any{"repos": repoNames, "images": images})
	writeJSON(*statsOut, map[string]any{
		"images": len(images), "errors": nerr, "error_samples": append([]string{}, errs...),
		"duration_s": dur, "images_per_s": float64(len(images)) / dur,
		"latency_ms": map[string]float64{"p50": pct(lat, 50), "p90": pct(lat, 90), "p99": pct(lat, 99), "max": maxLat},
	})
	if nerr > 0 {
		fmt.Fprintf(os.Stderr, "loadgen: %d errors, samples: %v\n", nerr, errs)
		os.Exit(1)
	}
}
