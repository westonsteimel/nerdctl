/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/containerd/cgroups"
	pkgapparmor "github.com/containerd/containerd/pkg/apparmor"
	"github.com/containerd/containerd/services/introspection"
	"github.com/containerd/nerdctl/pkg/defaults"
	"github.com/containerd/nerdctl/pkg/infoutil"
	"github.com/containerd/nerdctl/pkg/rootlessutil"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/urfave/cli/v2"
)

var infoCommand = &cli.Command{
	Name:   "info",
	Usage:  "Display system-wide information",
	Action: infoAction,
}

func infoAction(clicontext *cli.Context) error {
	w := clicontext.App.Writer
	fmt.Fprintf(w, "Client:\n")
	fmt.Fprintf(w, " Namespace:\t%s\n", clicontext.String("namespace"))
	fmt.Fprintf(w, " Debug Mode:\t%v\n", clicontext.Bool("debug"))

	client, ctx, cancel, err := newClient(clicontext)
	if err != nil {
		return err
	}
	defer cancel()
	daemonVersion, err := client.Version(ctx)
	if err != nil {
		return err
	}
	introService := client.IntrospectionService()
	daemonIntro, err := introService.Server(ctx, &ptypes.Empty{})
	if err != nil {
		return err
	}
	snapshotterPlugins, err := getSnapshotterNames(ctx, introService)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Server:\n")
	fmt.Fprintf(w, " Server Version: %s\n", daemonVersion.Version)
	// Storage Driver is not really Server concept for nerdctl, but mimics `docker info` output
	fmt.Fprintf(w, " Storage Driver: %s\n", clicontext.String("snapshotter"))
	fmt.Fprintf(w, " Logging Driver: json-file\n") // hard-coded
	fmt.Fprintf(w, " Cgroup Driver: %s\n", defaults.CgroupManager())
	cgVersion := 1
	if cgroups.Mode() == cgroups.Unified {
		cgVersion = 2
	}
	fmt.Fprintf(w, " Cgroup Version: %d\n", cgVersion)
	fmt.Fprintf(w, " Plugins:\n")
	fmt.Fprintf(w, "  Storage: %s\n", strings.Join(snapshotterPlugins, " "))
	fmt.Fprintf(w, " Security Options:\n")
	if pkgapparmor.HostSupports() {
		fmt.Fprintf(w, "  apparmor\n")
	}
	fmt.Fprintf(w, "  seccomp\n")
	fmt.Fprintf(w, "   Profile: default\n")
	if defaults.CgroupnsMode() == "private" {
		fmt.Fprintf(w, "  cgroupns\n")
	}
	if rootlessutil.IsRootlessChild() {
		fmt.Fprintf(w, "  rootless\n")
	}
	fmt.Fprintf(w, " Operating System: %s\n", infoutil.DistroName())
	fmt.Fprintf(w, " Kernel Version: %s\n", infoutil.UnameR())
	fmt.Fprintf(w, " ID: %s\n", daemonIntro.UUID)
	return nil
}

func getSnapshotterNames(ctx context.Context, introService introspection.Service) ([]string, error) {
	var names []string
	plugins, err := introService.Plugins(ctx, nil)
	if err != nil {
		return nil, err
	}
	for _, p := range plugins.Plugins {
		if strings.HasPrefix(p.Type, "io.containerd.snapshotter.") && p.InitErr == nil {
			names = append(names, p.ID)
		}
	}
	return names, nil
}
