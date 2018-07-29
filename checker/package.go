package checker

import (
	"strings"

	"github.com/b4stet/dependencies_checker/composer"
	"github.com/b4stet/dependencies_checker/sensiolabs"
)

type Package struct {
	Name             string
	IsRoot           bool
	InstalledVersion string
	Link             string
	Dependencies     []string
	Vulnerabilities  []sensiolabs.Advisory
}
type Packages []Package

func convert(pack *composer.Package) *Package {
	var deps []string
	for name, _ := range pack.Require {
		if name != "php" {
			deps = append(deps, name)
		}
	}

	return &Package{
		Name:             pack.Name,
		IsRoot:           pack.IsRoot,
		InstalledVersion: strings.Replace(pack.Version, "v", "", 1),
		Link:             pack.Source.Url,
		Dependencies:     deps,
	}
}

func (packs Packages) getPackage(packageName string) Package {
	for _, pack := range packs {
		if pack.Name == packageName {
			return pack
		}
	}

	return Package{}
}
