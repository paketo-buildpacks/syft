// Copyright 2018-2026 the original author or authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/paketo-buildpacks/libdependency/retrieve"
	"github.com/paketo-buildpacks/libdependency/upstream"
	"github.com/paketo-buildpacks/libdependency/versionology"
	"github.com/paketo-buildpacks/packit/v2/cargo"
)

const (
	id       = "syft"
	name     = "Syft"
	purlName = "anchore-syft"

	org  = "anchore"
	repo = "syft"
)

type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type release struct {
	TagName    string  `json:"tag_name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
}

type syftVersion struct {
	version *semver.Version
	tag     string
	assets  []asset
}

func (v syftVersion) Version() *semver.Version {
	return v.version
}

func main() {
	retrieve.NewMetadataWithPlatforms(id, getAllVersions, generateMetadata)
}

func getAllVersions() (versionology.VersionFetcherArray, error) {
	releases, err := fetchReleases(org, repo)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch releases\n%w", err)
	}

	var versions versionology.VersionFetcherArray
	for _, r := range releases {
		v, err := semver.NewVersion(strings.TrimPrefix(r.TagName, "v"))
		if err != nil {
			fmt.Printf("Skipping %s: unable to parse version\n", r.TagName)
			continue
		}

		versions = append(versions, syftVersion{version: v, tag: r.TagName, assets: r.Assets})
	}

	return versions, nil
}

func generateMetadata(versionFetcher versionology.VersionFetcher, platform retrieve.Platform) ([]versionology.Dependency, error) {
	version, ok := versionFetcher.(syftVersion)
	if !ok {
		return nil, fmt.Errorf("unexpected version type %T", versionFetcher)
	}

	versionString := version.version.String()

	archive := findAsset(version.assets, assetPattern(platform.Arch))
	if archive == nil {
		fmt.Printf("Skipping %s: missing %s/%s asset\n", versionString, platform.OS, platform.Arch)
		return nil, nil
	}

	source := fmt.Sprintf("https://github.com/%s/%s/archive/refs/tags/%s.tar.gz", org, repo, version.tag)
	sourceChecksum, err := upstream.GetSHA256OfRemoteFile(source)
	if err != nil {
		return nil, fmt.Errorf("unable to checksum %s\n%w", source, err)
	}

	checksum, err := upstream.GetSHA256OfRemoteFile(archive.BrowserDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("unable to checksum %s\n%w", archive.BrowserDownloadURL, err)
	}

	dependency := cargo.ConfigMetadataDependency{
		Arch:     platform.Arch,
		Checksum: fmt.Sprintf("sha256:%s", checksum),
		CPE:      fmt.Sprintf("cpe:2.3:a:anchore:syft:%s:*:*:*:*:*:*:*", versionString),
		ID:       id,
		Licenses: []interface{}{
			map[string]string{
				"type": "Apache-2.0",
				"uri":  "https://github.com/anchore/syft/blob/main/LICENSE",
			},
		},
		Name:           name,
		OS:             platform.OS,
		PURL:           retrieve.GeneratePURL(purlName, versionString, checksum, archive.BrowserDownloadURL),
		Source:         source,
		SourceChecksum: fmt.Sprintf("sha256:%s", sourceChecksum),
		Stacks:         []string{"*"},
		URI:            archive.BrowserDownloadURL,
		Version:        versionString,
	}

	d, err := versionology.NewDependency(dependency, fmt.Sprintf("%s-%s", platform.OS, platform.Arch))
	if err != nil {
		return nil, err
	}

	return []versionology.Dependency{d}, nil
}

func assetPattern(arch string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`syft_.+_linux_%s\.tar\.gz`, regexp.QuoteMeta(arch)))
}

func findAsset(assets []asset, pattern *regexp.Regexp) *asset {
	for i := range assets {
		if pattern.MatchString(assets[i].Name) {
			return &assets[i]
		}
	}

	return nil
}

func fetchReleases(owner, repo string) ([]release, error) {
	var all []release
	for page := 1; ; page++ {
		releases, err := fetchPage(owner, repo, page)
		if err != nil {
			return nil, err
		}

		if len(releases) == 0 {
			break
		}

		for _, r := range releases {
			if r.Prerelease {
				continue
			}
			all = append(all, r)
		}
	}

	return all, nil
}

func fetchPage(owner, repo string, page int) ([]release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?page=%d&per_page=100", owner, repo, page)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API returned status %d for %s", resp.StatusCode, url)
	}

	var releases []release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}

	return releases, nil
}
