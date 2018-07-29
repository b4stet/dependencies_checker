package sensiolabs

import (
	"regexp"
)

func (advs *Advisories) GetVulnerabilities(packageName string, packageVersion string) []Advisory {
	var vulns []Advisory

	for _, adv := range advs.Items {
		if packageName == adv.PackageName {
			if adv.isVulnerableVersion(packageVersion) == true {
				vulns = append(vulns, Advisory{
					PackageName:        packageName,
					Title:              adv.Title,
					Link:               adv.Link,
					CveIdentifier:      adv.CveIdentifier,
					PublishedAt:        adv.PublishedAt,
					VulnerableVersions: adv.VulnerableVersions,
				})
			}
		}
	}
	return vulns
}

func (adv *Advisory) isVulnerableVersion(packageVersion string) bool {
	versionConstraint := regexp.MustCompile(`([<>=]{1,2})(.*)`)

	test := false
	for _, version := range adv.VulnerableVersions {
		min := versionConstraint.FindStringSubmatch(version[0])
		if len(min) <= 0 {
			continue
		}
		sign := min[1]
		number := min[2]

		switch sign {
		case ">":
			if packageVersion > number {
				test = true
			}
		case ">=":
			if packageVersion >= number {
				test = true
			}
		}
		if test == false {
			continue
		}

		max := versionConstraint.FindStringSubmatch(version[1])
		if len(max) <= 0 {
			continue
		}
		sign = max[1]
		number = max[2]

		switch sign {
		case "<":
			if packageVersion >= number {
				test = false
			}
		case "<=":
			if packageVersion > number {
				test = false
			}
		}

		if test == true {
			break
		}
	}

	return test
}
