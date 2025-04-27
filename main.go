package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var tools = []string{"subfinder", "chaos", "gau", "unfurl", "curl", "jq"}

func checkDependencies() {
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Missing dependency: %s\n", tool)
			os.Exit(1)
		}
	}
}

func readLines(filename string) ([]string, error) {
	var lines []string

	file, err := os.Open(filename)
	if err != nil {
		return lines, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func runCommand(cmdName string, args ...string) ([]string, error) {
	cmd := exec.Command(cmdName, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	output := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	return output, nil
}

func filterSubdomains(subs []string, domain string) []string {
	var clean []string
	for _, sub := range subs {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub == "" || strings.Contains(sub, "*") {
			continue
		}
		parts := strings.Split(sub, ".")
		if len(parts) > 2 || strings.HasSuffix(sub, "."+domain) {
			clean = append(clean, sub)
		}
	}
	return clean
}

func processDomain(domain, program string, wg *sync.WaitGroup, lock *sync.Mutex) {
	defer wg.Done()

	fmt.Printf("[*] Processing domain: %s (%s)\n", domain, program)
	results := make(map[string]struct{})

	// Run subfinder
	if subs, err := runCommand("subfinder", "-d", domain, "-all", "-silent"); err == nil {
		for _, s := range filterSubdomains(subs, domain) {
			results[s] = struct{}{}
		}
	}

	// Run chaos
	if subs, err := runCommand("chaos", "-d", domain, "-silent"); err == nil {
		for _, s := range filterSubdomains(subs, domain) {
			results[s] = struct{}{}
		}
	}

	// Run gau and unfurl
	if gauOut, err := runCommand("gau", domain, "--threads", "10", "--subs"); err == nil {
		cmd := exec.Command("unfurl", "-u", "domains")
		stdin, _ := cmd.StdinPipe()
		stdout := &bytes.Buffer{}
		cmd.Stdout = stdout

		go func() {
			defer stdin.Close()
			for _, line := range gauOut {
				io.WriteString(stdin, line+"\n")
			}
		}()
		cmd.Run()

		unfurled := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		for _, s := range filterSubdomains(unfurled, domain) {
			results[s] = struct{}{}
		}
	}

	// Save results
	lock.Lock()
	defer lock.Unlock()

	subdir := filepath.Join("subdomains", program)
	os.MkdirAll(subdir, 0755)
	outfile := filepath.Join(subdir, domain+".txt")

	var final []string
	for sub := range results {
		final = append(final, sub)
	}
	sort.Strings(final)

	f, err := os.Create(outfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error writing %s: %v\n", outfile, err)
		return
	}
	defer f.Close()

	for _, sub := range final {
		f.WriteString(sub + "\n")
	}
	fmt.Printf("[+] %d subdomains written for %s\n", len(final), domain)
}

func mergeSubdomainsPerProgram() {
	subdir := "subdomains"

	entries, err := os.ReadDir(subdir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error reading subdomains directory: %v\n", err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		programPath := filepath.Join(subdir, entry.Name())

		var all []string

		err := filepath.Walk(programPath, func(path string, info os.FileInfo, err error) error {
			if strings.HasSuffix(path, ".txt") && !strings.HasSuffix(path, "all_subs.txt") {
				lines, err := readLines(path)
				if err == nil {
					all = append(all, lines...)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error walking %s: %v\n", programPath, err)
			continue
		}

		unique := make(map[string]struct{})
		for _, sub := range all {
			unique[sub] = struct{}{}
		}

		var final []string
		for sub := range unique {
			final = append(final, sub)
		}
		sort.Strings(final)

		outfile := filepath.Join(programPath, "all_subs.txt")
		f, err := os.Create(outfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error writing %s: %v\n", outfile, err)
			continue
		}
		defer f.Close()

		for _, sub := range final {
			f.WriteString(sub + "\n")
		}
		fmt.Printf("[+] Merged %d unique subdomains into %s\n", len(final), outfile)
	}
}

func main() {
	checkDependencies()

	programFiles, err := filepath.Glob("programs/*.txt")
	if err != nil || len(programFiles) == 0 {
		fmt.Println("[!] No program files found in programs/ directory.")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	var lock sync.Mutex

	for _, programFile := range programFiles {
		program := strings.TrimSuffix(filepath.Base(programFile), ".txt")
		domains, err := readLines(programFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error reading %s: %v\n", programFile, err)
			continue
		}
		for _, domain := range domains {
			wg.Add(1)
			go processDomain(domain, program, &wg, &lock)
		}
	}

	wg.Wait()
	fmt.Println("[*] All programs processed.")
	mergeSubdomainsPerProgram()
}
