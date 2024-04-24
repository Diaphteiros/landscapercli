// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors.
//
// SPDX-License-Identifier: Apache-2.0

package blueprints

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/go-logr/logr"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/tools/setup-envtest/env"
	"sigs.k8s.io/controller-runtime/tools/setup-envtest/remote"
	"sigs.k8s.io/controller-runtime/tools/setup-envtest/store"
	"sigs.k8s.io/controller-runtime/tools/setup-envtest/versions"
	"sigs.k8s.io/controller-runtime/tools/setup-envtest/workflows"
)

// var dependencyVersions = map[string]*dependency{
// 	"etcd": &dependency{
// 		Name: "etcd",
// 		Version: "v3.4.31",
// 		GenerateURL: func(version, opsy, arch string) string {
// 			ext := "tar.gz"
// 			if opsy == "darwin" || opsy == "windows" {
// 				ext = "zip"
// 			}
// 			return fmt.Sprintf("https://github.com/etcd-io/etcd/releases/download/%s/etcd-%s-%s-%s.%s", version, version, opsy, arch, ext)
// 		},
// 	},
// 	"kube-apiserver": &dependency{
// 		Name: "kube-apiserver",
// 		Version: "v1.29.3",
// 		GenerateURL: func(version, opsy, arch string) string {

// 		},
// 	},
// }

// type dependency struct {
// 	Name string
// 	Version string
// 	GenerateURL func(version, opsy, arch string) string
// }

type RenderOptions struct {
	depDir     string
	k8sVersion string
}

func (o *RenderOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.depDir, "dep-dir", "", "path to the envtest binary directory that contains subfolders with the etcd and kube-apiserver binaries")
	fs.StringVar(&o.k8sVersion, "k8s-version", "latest", "k8s version to use for simulation, either 'latest' or complete or partial k8s versions are supported (e.g. 1.27.x), see https://github.com/kubernetes-sigs/controller-runtime/blob/main/tools/setup-envtest/README.md for examples")
}

// NewRenderCommand creates a new local command to render a blueprint instance locally
func NewRenderCommand(ctx context.Context) *cobra.Command {
	opts := &RenderOptions{}
	cmd := &cobra.Command{
		Use: "render",
		//Args:    cobra.RangeArgs(1, 2),
		Example: "landscaper-cli blueprints render BLUEPRINT_DIR [all,deployitems,subinstallations,imports,exports]",
		Short:   "renders the given blueprint",
		Long: `
		Renders the blueprint with the given values files.
		All value files are merged whereas the later defined will overwrite the values of the previous ones
		
		By default all rendered resources are printed to stdout.
		Specific resources can be printed by adding a second argument.
		landscapercli local render [path to Blueprint directory] [resource]
		`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := opts.Complete(); err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}

			if err := opts.Run(); err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		},
	}

	opts.AddFlags(cmd.Flags())
	return cmd
}

func (o *RenderOptions) Complete() error { return nil }

func (o *RenderOptions) Run() error {
	assetPath, err := EnsureDependencies(o.depDir, o.k8sVersion)
	if err != nil {
		return fmt.Errorf("error verifying/downloading envtest binaries: %w", err)
	}

	// start envtest environment
	e := &envtest.Environment{
		BinaryAssetsDirectory: assetPath,
	}
	kcfg, err := e.Start()
	if err != nil {
		return fmt.Errorf("error starting envtest environment: %w", err)
	}
	defer e.Stop()

	// todo: templating
	fmt.Println(kcfg)

	return nil
}

// EnsureDependencies uses setup-envtest to download the kube-apiserver and etcd binaries, if required.
func EnsureDependencies(binDir, k8sVersion string) (string, error) {
	if binDir == "" {
		dataDir, err := store.DefaultStoreDir()
		if err != nil {
			return "", fmt.Errorf("unable to determine setup-envtest default binary location, set --dep-dir to overwrite manually")
		}
		binDir = dataDir
	}

	var version versions.Spec
	switch k8sVersion {
	case "", "latest":
		version = versions.LatestVersion
	default:
		var err error
		version, err = versions.FromExpr(k8sVersion)
		if err != nil {
			return "", fmt.Errorf("version cannot be parsed, use a valid version or 'latest': %w", err)
		}
	}

	// setup-envtest prints the path to stdout, so we have to capture it from there
	stdout := os.Stdout
	defer func() {
		os.Stdout = stdout
	}()
	r, w, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("error constructing pipe: %w", err)
	}
	defer r.Close()
	os.Stdout = w

	// run setup-envtest
	workflows.Use{PrintFormat: env.PrintPath}.Do(&env.Env{
		Log: logr.Discard(),
		Client: &remote.Client{
			Log:    logr.Discard(),
			Bucket: "kubebuilder-tools",
			Server: "storage.googleapis.com",
		},
		VerifySum:     true,
		ForceDownload: false,
		NoDownload:    false,
		Platform: versions.PlatformItem{
			Platform: versions.Platform{
				OS:   runtime.GOOS,
				Arch: runtime.GOARCH,
			},
		},
		FS:      afero.Afero{Fs: afero.NewOsFs()},
		Store:   store.NewAt(binDir),
		Out:     os.Stdout,
		Version: version,
	})

	// read the asset path previously written into the pipe
	w.Close()
	assetPath, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("error reading asset path from pipe: %w", err)
	}
	return string(assetPath), nil
}
