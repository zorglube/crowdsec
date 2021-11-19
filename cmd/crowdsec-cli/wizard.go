package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type detect struct {
	LogFiles      []string `json:"log_files"`
	JournalCTL    []string `json:"journalctl"`
	ServiceName   []string `json:"services_name"`
	Collections   []string `json:"collections"`
	Parsers       []string `json:"parsers"`
	Scenarios     []string `json:"scenarios"`
	PostOverflows []string `json:"postoverflows"`
	Type          string   `json:"type"`
}

type State struct {
	Service           string
	Collections       []string
	Parsers           []string
	Scenarios         []string
	PostOverflows     []string
	Type              string
	LogsPath          []string
	JournalCTLFilters []string
	ServicesName      []string // for windows
}

type detectionManager struct {
	Filepath string
	OS       map[string]*detect `json:"os"`
	Services map[string]*detect `json:"services"`
	State    map[string]*State
}

// 1 month ago
var fileOldLimit = time.Now().AddDate(0, -1, 0)

const journalCTlOldLimit = "1 month ago"
const journalctlCmd = "journalctl"

func NewServiceDetect(filepath string) (*detectionManager, error) {
	sd := &detectionManager{Filepath: filepath, State: make(map[string]*State)}
	jsonFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return sd, err
	}
	err = json.Unmarshal(jsonFile, sd)
	return sd, err
}

func isFileOlder(t time.Time, limit time.Time) bool {
	return t.Before(limit)
}

func detectService(serviceName string, detection *detect) (*State, bool, error) {
	detected := false
	state := &State{
		Service:           serviceName,
		Type:              detection.Type,
		LogsPath:          make([]string, 0),
		JournalCTLFilters: make([]string, 0),
		Collections:       detection.Collections,
		Parsers:           detection.Parsers,
		Scenarios:         detection.Scenarios,
		PostOverflows:     detection.PostOverflows,
	}

	for _, filePath := range detection.LogFiles {
		files, err := filepath.Glob(filePath)
		if err != nil {
			continue
		}
		if len(files) == 0 {
			log.Debugf("No matching files for pattern %s", filePath)
			continue
		}

		// check if at least one file is younger than 1 month
		ok := false
		for _, file := range files {
			fileInfo, err := os.Stat(file)
			if err != nil {
				continue
			}
			if isFileOlder(fileInfo.ModTime(), fileOldLimit) {
				continue
			}
			ok = true
			break
		}
		if ok {
			detected = true
			state.LogsPath = append(state.LogsPath, filePath)
		}
	}

	for _, journalCTLFilter := range detection.JournalCTL {
		args := []string{journalCTLFilter, "--since", journalCTlOldLimit}
		cmd := exec.CommandContext(context.Background(), journalctlCmd, args...)
		stdout, err := cmd.Output()
		if err != nil {
			log.Errorf("checking journalctl filter '%s' return error: %s", journalCTLFilter, err)
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(stdout))
		ok := true
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "No entries") {
				log.Debugf("no entries since '%s' in journalctl '%s' filter, continue", journalCTlOldLimit, journalCTLFilter)
				ok = false
				break
			}
		}
		if ok {
			detected = true
			state.JournalCTLFilters = append(state.JournalCTLFilters, journalCTLFilter)
		}
	}

	return state, detected, nil
}

func (d *detectionManager) Detect() error {
	var err error

	log.Debugf("Detected OS: %s", runtime.GOOS)
	err = d.DetectOS(runtime.GOOS)
	if err != nil {
		return err
	}

	for serviceName := range d.Services {
		err = d.DetectService(serviceName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *detectionManager) Apply(config *csconfig.CrowdsecServiceCfg) error {
	for serviceName, service := range d.State {
		log.Printf("service: %s|%+v", serviceName, service)
		// check if service already configured
		dataSourceExist := false
		for _, dataSource := range dataSources {
			for logFile := range service.LogsPath {
				for filenames := range dataSource.
			}
		}
	}

	return nil
}

func (d *detectionManager) DetectOS(osName string) error {
	var ok bool
	var err error
	var detectedOS *detect

	if detectedOS, ok = d.OS[osName]; !ok {
		return fmt.Errorf("os '%s' not supported", osName)
	}
	state, detected, err := detectService(osName, detectedOS)
	if err != nil {
		return err
	}

	if detected {
		d.State[osName] = state
	}
	return nil
}

func (d *detectionManager) Print() {
	for serviceName, service := range d.State {
		fmt.Printf("%s detected\n", strings.Title(serviceName))
		if len(service.LogsPath) > 0 {
			fmt.Printf("  * logs files found:\n")
			for _, logPath := range service.LogsPath {
				fmt.Printf("      - %s\n", logPath)
			}
		}
		if len(service.JournalCTLFilters) > 0 {
			fmt.Printf("  * journalctl found:\n")
			for _, journalctl := range service.JournalCTLFilters {
				fmt.Printf("      - %s\n", journalctl)
			}
		}
	}
}

func (d *detectionManager) DetectService(serviceName string) error {
	var ok bool
	var err error
	var service *detect

	if service, ok = d.Services[serviceName]; !ok {
		return fmt.Errorf("service '%s' not found or can't be detected", service)
	}

	state, detected, err := detectService(serviceName, service)
	if err != nil {
		return err
	}
	if detected {
		d.State[serviceName] = state
	}
	return nil
}

func NewWizardCmd() *cobra.Command {
	var cmdWizard = &cobra.Command{
		Use:               "wizard [action]",
		Short:             "Help to configure crowdsec",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadCrowdsec(); err != nil || csConfig.DisableAgent {
				log.Fatal("CrowdSec agent is not configured or disabled, can't run the wizard")
			}
			return nil
		},
	}

	var apply bool
	var reconfigure bool
	var serviceDetectionFile string
	var service string

	var cmdWizardDetect = &cobra.Command{
		Use:               "detect",
		Short:             "Detect running services, generate acquisitions and install collections",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			serviceDetector, err := NewServiceDetect(serviceDetectionFile)
			if err != nil {
				log.Fatalf("unable to load detection services: %s", err)
			}

			if err := serviceDetector.Detect(); err != nil {
				log.Fatalf("unable to detect services: %s", err)
			}
			serviceDetector.Print()
			if apply {
				if err := serviceDetector.Apply(csConfig.Crowdsec); err != nil {
					log.Fatalf("unable to apply configuration: %s", err)
				}
			}

		},
	}
	cmdWizardDetect.Flags().StringVarP(&serviceDetectionFile, "file", "f", "/etc/crowdsec/service_detection.json", "File to detect services")
	cmdWizardDetect.Flags().BoolVarP(&apply, "apply", "a", false, "Apply the detection")
	cmdWizardDetect.Flags().StringVarP(&service, "service", "s", "", "Service to detect")
	cmdWizardDetect.Flags().BoolVarP(&reconfigure, "reconfigure", "r", false, "Reconfigure all the acquisitions/collections")
	cmdWizard.AddCommand(cmdWizardDetect)

	return cmdWizard
}
