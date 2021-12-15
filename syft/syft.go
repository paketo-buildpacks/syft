/*
 * Copyright 2018-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package syft

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/crush"
)

const UpdateCheckEnvVar = "SYFT_CHECK_FOR_APP_UPDATE"

type Syft struct {
	LayerContributor libpak.DependencyLayerContributor
	Logger           bard.Logger
}

func NewSyft(dependency libpak.BuildpackDependency, cache libpak.DependencyCache) (Syft, libcnb.BOMEntry) {
	contributor, entry := libpak.NewDependencyLayer(dependency, cache, libcnb.LayerTypes{
		Cache: true,
		Build: true,
	})
	return Syft{LayerContributor: contributor}, entry
}

func (w Syft) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	w.LayerContributor.Logger = w.Logger

	return w.LayerContributor.Contribute(layer, func(artifact *os.File) (libcnb.Layer, error) {
		w.Logger.Bodyf("Expanding to %s", layer.Path)
		if err := crush.ExtractTarGz(artifact, layer.Path, 0); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to expand Syft\n%w", err)
		}

		binDir := filepath.Join(layer.Path, "bin")

		if err := os.MkdirAll(binDir, 0755); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to mkdir\n%w", err)
		}

		if err := os.Symlink(filepath.Join(layer.Path, "syft"), filepath.Join(binDir, "syft")); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to symlink Syft\n%w", err)
		}
		// We should skip checking for version updates for syft. This causes timeouts and slowdowns
		// in air-gapped environments.
		layer.BuildEnvironment.Default(UpdateCheckEnvVar, "false")
		return layer, nil
	})
}

func (w Syft) Name() string {
	return w.LayerContributor.LayerName()
}
