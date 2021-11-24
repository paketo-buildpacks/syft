# `gcr.io/paketo-buildpacks/syft`

The Paketo Syft Buildpack is a Cloud Native Buildpack that contributes the Syft CLI which can be used to generate SBoM information.

## Behavior

This buildpack will participate all the following conditions are met

* Another buildpack requires `syft`

The buildpack will do the following:

* Contributes Syft to a layer marked `build` and `cache` with command on `$PATH`

## License

This buildpack is released under version 2.0 of the [Apache License][a].

[a]: http://www.apache.org/licenses/LICENSE-2.0
