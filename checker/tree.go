package checker

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
)

var (
	red = color.New(color.FgRed).SprintFunc()
)

type Tree struct {
	Nodes Nodes
}

type Node struct {
	Name         string
	IsVulnerable bool
	Children     Nodes
}
type Nodes []*Node

func GetDependenciesTree(packs Packages) Tree {
	var tree Tree

	for _, pack := range packs {
		if pack.IsRoot == true {
			tree.Nodes = append(tree.Nodes, &Node{
				Name:         pack.Name,
				IsVulnerable: false,
			})
		}
	}

	leaves := tree.Nodes
	for len(leaves) > 0 {
		for _, leave := range leaves {
			pack := packs.getPackage(leave.Name)
			if len(pack.Vulnerabilities) > 0 {
				leave.IsVulnerable = true
			}

			for _, dep := range pack.Dependencies {
				leave.Children = append(leave.Children, &Node{
					Name:         dep,
					IsVulnerable: false,
				})
			}
		}
		leaves = leaves.getLeaves()
	}

	return tree
}

func (nodes Nodes) getLeaves() Nodes {
	var leaves []*Node
	for _, node := range nodes {
		if len(node.Children) > 0 {
			leaves = append(leaves, node.Children...)
		}
	}
	return leaves
}

func (tree Tree) PrintTree(w io.Writer) {
	for _, node := range tree.Nodes {
		fmt.Fprintf(w, "%s\n", node.printNode(0))
	}
}

func (node *Node) printNode(depth int) string {
	name := node.Name
	if node.IsVulnerable == true {
		name = red(name)
	}
	output := strings.Repeat("      ", depth) + " |- " + name

	for _, child := range node.Children {
		output = output + "\n |" + child.printNode(depth+1)
	}

	return output
}
