package hubtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type HubTest struct {
	CrowdSecPath            string
	CscliPath               string
	HubPath                 string
	HubTestPath             string //generic parser/scenario tests .tests
	HubWaapTestPath         string //dir specific to waap tests .waap-tests
	HubIndexFile            string
	TemplateConfigPath      string
	TemplateProfilePath     string
	TemplateSimulationPath  string
	TemplateAcquisPath      string
	TemplateWaapProfilePath string
	HubIndex                *cwhub.Hub
	Tests                   []*HubTestItem
}

const (
	templateConfigFile      = "template_config.yaml"
	templateSimulationFile  = "template_simulation.yaml"
	templateProfileFile     = "template_profiles.yaml"
	templateAcquisFile      = "template_acquis.yaml"
	templateWaapProfilePath = "template_waap-profile.yaml"
)

func NewHubTest(hubPath string, crowdsecPath string, cscliPath string, isWaapTest bool) (HubTest, error) {
	hubPath, err := filepath.Abs(hubPath)
	if err != nil {
		return HubTest{}, fmt.Errorf("can't get absolute path of hub: %+v", err)
	}

	// we can't use hubtest without the hub
	if _, err = os.Stat(hubPath); os.IsNotExist(err) {
		return HubTest{}, fmt.Errorf("path to hub '%s' doesn't exist, can't run", hubPath)
	}
	// we can't use hubtest without crowdsec binary
	if _, err = exec.LookPath(crowdsecPath); err != nil {
		if _, err = os.Stat(crowdsecPath); os.IsNotExist(err) {
			return HubTest{}, fmt.Errorf("path to crowdsec binary '%s' doesn't exist or is not in $PATH, can't run", crowdsecPath)
		}
	}

	// we can't use hubtest without cscli binary
	if _, err = exec.LookPath(cscliPath); err != nil {
		if _, err = os.Stat(cscliPath); os.IsNotExist(err) {
			return HubTest{}, fmt.Errorf("path to cscli binary '%s' doesn't exist or is not in $PATH, can't run", cscliPath)
		}
	}

	if isWaapTest {
		HubTestPath := filepath.Join(hubPath, "./.waap-tests/")
		hubIndexFile := filepath.Join(hubPath, ".index.json")

		local := &csconfig.LocalHubCfg{
			HubDir:         hubPath,
			HubIndexFile:   hubIndexFile,
			InstallDir:     HubTestPath,
			InstallDataDir: HubTestPath,
		}

		hub, err := cwhub.NewHub(local, nil, false)
		if err != nil {
			return HubTest{}, fmt.Errorf("unable to load hub: %s", err)
		}

		return HubTest{
			CrowdSecPath:            crowdsecPath,
			CscliPath:               cscliPath,
			HubPath:                 hubPath,
			HubTestPath:             HubTestPath,
			HubIndexFile:            hubIndexFile,
			TemplateConfigPath:      filepath.Join(HubTestPath, templateConfigFile),
			TemplateProfilePath:     filepath.Join(HubTestPath, templateProfileFile),
			TemplateSimulationPath:  filepath.Join(HubTestPath, templateSimulationFile),
			TemplateWaapProfilePath: filepath.Join(HubTestPath, templateWaapProfilePath),
			TemplateAcquisPath:      filepath.Join(HubTestPath, templateAcquisFile),
			HubIndex:                hub,
		}, nil
	}

	HubTestPath := filepath.Join(hubPath, "./.tests/")

	hubIndexFile := filepath.Join(hubPath, ".index.json")

	local := &csconfig.LocalHubCfg{
		HubDir:         hubPath,
		HubIndexFile:   hubIndexFile,
		InstallDir:     HubTestPath,
		InstallDataDir: HubTestPath,
	}

	hub, err := cwhub.NewHub(local, nil, false)
	if err != nil {
		return HubTest{}, fmt.Errorf("unable to load hub: %s", err)
	}

	return HubTest{
		CrowdSecPath:           crowdsecPath,
		CscliPath:              cscliPath,
		HubPath:                hubPath,
		HubTestPath:            HubTestPath,
		HubIndexFile:           hubIndexFile,
		TemplateConfigPath:     filepath.Join(HubTestPath, templateConfigFile),
		TemplateProfilePath:    filepath.Join(HubTestPath, templateProfileFile),
		TemplateSimulationPath: filepath.Join(HubTestPath, templateSimulationFile),
		HubIndex:               hub,
	}, nil
}

func (h *HubTest) LoadTestItem(name string) (*HubTestItem, error) {
	HubTestItem := &HubTestItem{}

	testItem, err := NewTest(name, h)
	if err != nil {
		return HubTestItem, err
	}

	h.Tests = append(h.Tests, testItem)

	return testItem, nil
}

func (h *HubTest) LoadAllTests() error {
	testsFolder, err := os.ReadDir(h.HubTestPath)
	if err != nil {
		return err
	}

	for _, f := range testsFolder {
		if f.IsDir() {
			if _, err := h.LoadTestItem(f.Name()); err != nil {
				return fmt.Errorf("while loading %s: %w", f.Name(), err)
			}
		}
	}

	return nil
}
