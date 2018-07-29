package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/b4stet/dependencies_checker/checker"
	"github.com/b4stet/dependencies_checker/sensiolabs"
)

func main() {
	verbosityPtr := flag.Bool("v", false, "enable verbosity for details in the report.")
	composerLockPtr := flag.String("lock", "./tests/composer.lock", "path to composer.lock.")
	composerJsonPtr := flag.String("json", "./tests/composer.json", "path to composer.json.")
	flag.Parse()

	fmt.Printf("Dependencies Security Checker \n")
	fmt.Printf("Author: b4stet\n\n")

	advs, err := sensiolabs.GetAdvisories()
	if err != nil {
		log.Fatalf("ERROR: Failed to fetch Sensiolabs Advisories [%v]", err)
	}

	project := &checker.Project{
		JsonFile: *composerJsonPtr,
		LockFile: *composerLockPtr,
	}
	results, err := project.Check(advs)
	if err != nil {
		log.Fatalf("ERROR: %v\n", err)
	}

	writer := bufio.NewWriter(os.Stdout)
	results.PrintReport(writer, *verbosityPtr)
	writer.Flush()

}
