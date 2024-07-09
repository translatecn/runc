package main

import (
	"fmt"
	runc "github.com/opencontainers/runc/cmd"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
	"os"
	"runtime"
	"strings"
)

func main() {
	app := cli.NewApp()
	app.Name = "runc"
	app.Usage = runc.Usage

	v := []string{runc.Version}

	if runc.GitCommit != "" {
		v = append(v, "commit: "+runc.GitCommit)
	}
	v = append(v, "spec: "+specs.Version)
	v = append(v, "go: "+runtime.Version())

	major, minor, micro := seccomp.Version()
	if major+minor+micro > 0 {
		v = append(v, fmt.Sprintf("libseccomp: %d.%d.%d", major, minor, micro))
	}
	app.Version = strings.Join(v, "\n")

	xdgRuntimeDir := ""
	root := "/run/runc"
	if runc.ShouldHonorXDGRuntimeDir() {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			root = runtimeDir + "/runc"
			xdgRuntimeDir = root
		}
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug logging",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "set the log file to write runc logs to (default is '/dev/stderr')",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "set the log format ('text' (default), or 'json')",
		},
		cli.StringFlag{
			Name:  "root",
			Value: root,
			Usage: "root directory for storage of container state (this should be located in tmpfs)",
		},
		cli.StringFlag{
			Name:  "criu",
			Value: "criu",
			Usage: "path to the criu binary used for checkpoint and restore",
		},
		cli.BoolFlag{
			Name:  "systemd-cgroup",
			Usage: "enable systemd cgroup support, expects cgroupsPath to be of form \"slice:prefix:name\" for e.g. \"system.slice:runc:434234\"",
		},
		cli.StringFlag{
			Name:  "rootless",
			Value: "auto",
			Usage: "ignore cgroup permission errors ('true', 'false', or 'auto')",
		},
	}
	app.Commands = []cli.Command{
		runc.CheckpointCommand,
		runc.CreateCommand, // ✅
		runc.DeleteCommand, // ✅
		runc.EventsCommand,
		runc.ExecCommand,
		runc.KillCommand,  // ✅
		runc.ListCommand,  // ✅
		runc.PauseCommand, // ✅
		runc.PsCommand,    // ✅
		runc.RestoreCommand,
		runc.ResumeCommand, // ✅
		runc.RunCommand,
		runc.SpecCommand,
		runc.StartCommand,
		runc.StateCommand,
		runc.UpdateCommand,
		runc.FeaturesCommand,
	}
	app.Before = func(context *cli.Context) error {
		if !context.IsSet("root") && xdgRuntimeDir != "" {
			// According to the XDG specification, we need to set anything in
			// XDG_RUNTIME_DIR to have a sticky bit if we don't want it to get
			// auto-pruned.
			if err := os.MkdirAll(root, 0o700); err != nil {
				fmt.Fprintln(os.Stderr, "the path in $XDG_RUNTIME_DIR must be writable by the user")
				runc.Fatal(err)
			}
			if err := os.Chmod(root, os.FileMode(0o700)|os.ModeSticky); err != nil {
				fmt.Fprintln(os.Stderr, "you should check permission of the path in $XDG_RUNTIME_DIR")
				runc.Fatal(err)
			}
		}
		if err := runc.ReviseRootDir(context); err != nil {
			return err
		}

		return runc.ConfigLogrus(context)
	}

	// If the command returns an error, cli takes upon itself to print
	// the error on cli.ErrWriter and exit.
	// Use our own writer here to ensure the log gets sent to the right location.
	cli.ErrWriter = &runc.FatalWriter{cli.ErrWriter}
	if err := app.Run(os.Args); err != nil {
		runc.Fatal(err)
	}
}
