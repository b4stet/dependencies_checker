package checker

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

func (results *Results) PrintReport(w io.Writer, verbosity bool) {
	ok := color.New(color.FgGreen)
	ko := color.New(color.FgRed)

	if verbosity == true {
		fmt.Fprintf(w, "[+] Infos\n")
		fmt.Fprintf(w, " | Advisories source is %s, last updated at %s, and contains %d items.\n",
			results.AdvisorySource,
			results.AdvisoryLastBuild,
			results.AdvisorySize,
		)
		fmt.Fprintf(w, " | The file composer.lock contains %d packages.\n\n", len(results.Packages))
	}

	fmt.Fprintf(w, "[+] Summary\n")
	for _, pack := range results.Packages {
		if len(pack.Vulnerabilities) == 0 {
			ok.Fprintf(w, " | [ok] %s (v%s) has no known vulnerabilitie(s).\n",
				pack.Name, pack.InstalledVersion,
			)
		} else {
			ko.Fprintf(w, " | [ko] %s (v%s) has %d known vulnerabilitie(s).\n",
				pack.Name, pack.InstalledVersion, len(pack.Vulnerabilities),
			)
		}
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "[+] Details\n")
	for _, pack := range results.Packages {
		if len(pack.Vulnerabilities) > 0 {
			ko.Fprintf(w, "[-] %v is installed in v%v (source: %v). This version is vulnerable to:\n",
				pack.Name, pack.InstalledVersion, pack.Link,
			)

			for _, vuln := range pack.Vulnerabilities {
				ko.Fprintf(w, " *")
				year, month, day := vuln.PublishedAt.Date()

				fmt.Fprintf(w, " Advisory:%s\n", vuln.Title)
				fmt.Fprintf(w, "   | Link:               %s\n", vuln.Link)
				fmt.Fprintf(w, "   | Published at:       %d %s %d\n", year, month, day)
				fmt.Fprintf(w, "   | Vulnerable version: %v\n", vuln.VulnerableVersions)
				fmt.Fprintf(w, "   | CVE:                %s\n", vuln.CveIdentifier)
			}

			fmt.Fprintf(w, "\n")
		}
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "[+] Dependencies tree of the project\n")
	results.DepsTree.PrintTree(w)
	fmt.Fprintf(w, "\n")
}
