package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Node struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Locator   string `json:"locator"`
	Kind      string `json:"kind"`
	Language  string `json:"language"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
}

type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Action   string `json:"action"`
	Evidence string `json:"evidence"`
	Resolver string `json:"resolver"`
}

type Output struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type functionRecord struct {
	ID   string
	File string
	Decl *ast.FuncDecl
	Fset *token.FileSet
}

var excluded = map[string]bool{
	".git": true, ".workflow": true, ".idea": true, ".vscode": true,
	".venv": true, "venv": true, "node_modules": true, "dist": true,
	"build": true, "coverage": true, "vendor": true, "__pycache__": true,
}

func receiverName(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return receiverName(x.X)
	case *ast.IndexExpr:
		return receiverName(x.X)
	case *ast.IndexListExpr:
		return receiverName(x.X)
	default:
		return ""
	}
}

func callLeaf(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	default:
		return ""
	}
}

func main() {
	rootFlag := flag.String("root", ".", "repository root")
	flag.Parse()
	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		panic(err)
	}

	var records []functionRecord
	var nodes []Node

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && excluded[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			qual := fn.Name.Name
			kind := "function"
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				recv := receiverName(fn.Recv.List[0].Type)
				if recv != "" {
					qual = recv + "." + fn.Name.Name
				}
				kind = "method"
			}
			id := rel + "::" + qual
			nodes = append(nodes, Node{
				ID: id, Label: id, Locator: id, Kind: kind, Language: "Go",
				LineStart: fset.Position(fn.Pos()).Line,
				LineEnd: fset.Position(fn.End()).Line,
			})
			records = append(records, functionRecord{ID: id, File: rel, Decl: fn, Fset: fset})
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	byFileLeaf := map[string][]string{}
	byLeaf := map[string][]string{}
	for _, rec := range records {
		qual := strings.SplitN(rec.ID, "::", 2)[1]
		parts := strings.Split(qual, ".")
		leaf := parts[len(parts)-1]
		byFileLeaf[rec.File+"\x00"+leaf] = append(byFileLeaf[rec.File+"\x00"+leaf], rec.ID)
		byLeaf[leaf] = append(byLeaf[leaf], rec.ID)
	}

	seen := map[string]bool{}
	var edges []Edge
	for _, rec := range records {
		ast.Inspect(rec.Decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			leaf := callLeaf(call.Fun)
			if leaf == "" {
				return true
			}
			candidates := byFileLeaf[rec.File+"\x00"+leaf]
			if len(candidates) != 1 {
				candidates = byLeaf[leaf]
			}
			if len(candidates) != 1 || candidates[0] == rec.ID {
				return true
			}
			target := candidates[0]
			key := rec.ID + "\x00" + target + "\x00" + leaf
			if seen[key] {
				return true
			}
			seen[key] = true
			edges = append(edges, Edge{
				From: rec.ID, To: target, Action: leaf,
				Evidence: "STATIC", Resolver: "go_ast",
			})
			return true
		})
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From { return edges[i].From < edges[j].From }
		if edges[i].To != edges[j].To { return edges[i].To < edges[j].To }
		return edges[i].Action < edges[j].Action
	})

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(Output{Nodes: nodes, Edges: edges}); err != nil {
		panic(err)
	}
}
