// Command max-connect opens a human-operated SSH, SFTP, or Windows RDP session.
// It does not use MAX Remote Commander's LLM command relay or agent permissions.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type invocation struct {
	program string
	args    []string
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validUser(user string) bool {
	if user == "" || len(user) > 128 || user[0] == '-' {
		return false
	}
	for _, c := range user {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func buildForOS(goos string, arguments []string) (invocation, error) {
	if len(arguments) == 0 {
		return invocation{}, errors.New("mode required: terminal, files, check, or desktop")
	}
	mode := arguments[0]
	if mode != "terminal" && mode != "files" && mode != "check" && mode != "desktop" {
		return invocation{}, fmt.Errorf("unsupported mode %q", mode)
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	host := flags.String("host", "", "destination host on LAN/VPN")
	user := flags.String("user", "", "SSH login username")
	port := flags.Int("port", 0, "destination port (SSH: 22, RDP: 3389)")
	identity := flags.String("identity", "", "existing SSH private-key file")
	knownHosts := flags.String("known-hosts", "", "existing SSH known_hosts file")
	if err := flags.Parse(arguments[1:]); err != nil {
		return invocation{}, err
	}
	if flags.NArg() != 0 {
		return invocation{}, errors.New("unexpected positional arguments; remote commands are not accepted")
	}
	if !validHost(*host) {
		return invocation{}, errors.New("--host must be a valid IP address or DNS hostname")
	}
	portExplicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portExplicit = true
		}
	})
	if !portExplicit {
		if mode == "desktop" {
			*port = 3389
		} else {
			*port = 22
		}
	}
	if *port < 1 || *port > 65535 {
		return invocation{}, errors.New("--port must be between 1 and 65535")
	}
	if mode == "desktop" {
		if *user != "" || *identity != "" || *knownHosts != "" {
			return invocation{}, errors.New("desktop mode uses OS-native authentication; SSH flags are unsupported")
		}
		if goos != "windows" {
			return invocation{}, errors.New("desktop mode currently requires Windows mstsc.exe; other RDP clients are not yet integrated")
		}
		address := *host
		if strings.Contains(address, ":") {
			address = "[" + address + "]"
		}
		return invocation{program: "mstsc.exe", args: []string{"/v:" + address + ":" + strconv.Itoa(*port)}}, nil
	}
	if !validUser(*user) {
		return invocation{}, errors.New("--user is required and must contain only username characters")
	}
	if *identity != "" && !regularFile(*identity) {
		return invocation{}, errors.New("--identity must name an existing regular file")
	}
	if *knownHosts != "" && !regularFile(*knownHosts) {
		return invocation{}, errors.New("--known-hosts must name an existing regular file")
	}

	// Disable user SSH config and refuse unknown/changed host keys. No shell or
	// user-supplied SSH options are evaluated. The OS SSH/SFTP client owns auth.
	args := []string{
		"-F", "none",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "ForwardAgent=no",
		"-o", "PermitLocalCommand=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ConnectTimeout=10",
	}
	if *identity != "" {
		args = append(args, "-i", *identity)
	}
	if *knownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+*knownHosts)
	}
	if mode == "files" {
		remote := *user + "@" + *host
		if strings.Contains(*host, ":") {
			remote = *user + "@[" + *host + "]"
		}
		args = append(args, "-P", strconv.Itoa(*port), "--", remote)
		return invocation{program: "sftp", args: args}, nil
	}
	if mode == "check" {
		args = append(args, "-o", "BatchMode=yes", "-T")
	}
	args = append(args, "-p", strconv.Itoa(*port), "-l", *user, "--", *host)
	if mode == "check" {
		args = append(args, "exit", "0") // Fixed no-op on POSIX shells and Windows PowerShell/CMD.
	}
	return invocation{program: "ssh", args: args}, nil
}

func run(args []string) error {
	inv, err := buildForOS(runtime.GOOS, args)
	if err != nil {
		return err
	}
	command := exec.Command(inv.program, inv.args...) // #nosec G204: fixed client allowlist; no shell.
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "max-connect:", err)
		os.Exit(2)
	}
}
