package checker

import (
	"time"

	"github.com/b4stet/dependencies_checker/composer"
	"github.com/b4stet/dependencies_checker/sensiolabs"
)

type Project struct {
	Verbosity bool
	JsonFile  string
	LockFile  string
}

type Results struct {
	AdvisorySource    string
	AdvisoryLastBuild time.Time
	AdvisorySize      int
	Packages          Packages
	DepsTree          Tree
}

func (project *Project) Check(advs *sensiolabs.Advisories) (*Results, error) {
	var results Results
	results.AdvisorySource = advs.Source
	results.AdvisoryLastBuild = advs.LastBuildAt
	results.AdvisorySize = len(advs.Items)

	composerPackages, err := composer.GetInstalledPackages(project.JsonFile, project.LockFile)
	if err != nil {
		return nil, err
	}

	for _, composerPackage := range composerPackages {
		pack := convert(composerPackage)
		pack.Vulnerabilities = advs.GetVulnerabilities(pack.Name, pack.InstalledVersion)
		results.Packages = append(results.Packages, *pack)
	}

	results.DepsTree = GetDependenciesTree(results.Packages)

	return &results, nil
}
