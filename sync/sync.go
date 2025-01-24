package sync

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/please-build/buildtools/build"
	"github.com/please-build/buildtools/labels"
	"golang.org/x/mod/modfile"
	"golang.org/x/sync/errgroup"

	"github.com/please-build/puku/config"
	"github.com/please-build/puku/edit"
	"github.com/please-build/puku/graph"
	"github.com/please-build/puku/licences"
	"github.com/please-build/puku/logging"
	"github.com/please-build/puku/please"
	"github.com/please-build/puku/proxy"
)

var log = logging.GetLogger()

type syncer struct {
	plzConf          *please.Config
	graph            *graph.Graph
	licences         *licences.Licenses
	updateTransitive bool
}

const ReplaceLabel = "go_replace_directive"

func newSyncer(plzConf *please.Config, g *graph.Graph, updateTransitive bool) *syncer {
	p := proxy.New(proxy.DefaultURL)
	l := licences.New(p, g)
	return &syncer{
		plzConf:          plzConf,
		graph:            g,
		licences:         l,
		updateTransitive: updateTransitive,
	}
}

// Sync constructs the syncer struct and initiates the sync.
// NB. the Graph is to be constructed in the calling code because it's useful
// for it to be available outside the package for testing.
func Sync(plzConf *please.Config, g *graph.Graph, updateTransitive bool) error {
	s := newSyncer(plzConf, g, updateTransitive)
	if err := s.sync(); err != nil {
		return err
	}
	return s.graph.FormatFiles()
}

// SyncToStdout constructs the syncer and outputs the synced build file to stdout.
func SyncToStdout(format string, plzConf *please.Config, g *graph.Graph, updateTransitive bool) error { //nolint
	s := newSyncer(plzConf, g, updateTransitive)
	if err := s.sync(); err != nil {
		return err
	}
	return s.graph.FormatFilesWithWriter(os.Stdout, format)
}

func (s *syncer) sync() error {
	if s.plzConf.ModFile() == "" {
		return nil
	}

	conf, err := config.ReadConfig(".")
	if err != nil {
		return err
	}

	file, err := s.graph.LoadFile(conf.GetThirdPartyDir())
	if err != nil {
		return err
	}

	existingRules, err := s.readModules(file)
	if err != nil {
		return fmt.Errorf("failed to read third party rules: %v", err)
	}

	if err := s.syncModFile(conf, file, existingRules); err != nil {
		return err
	}
	return nil
}

// listModule represents a module returned from the `go list` command, with an extra field `InGoMod`
// to represent whether the module is listed in the go.mod file.
type listModule struct {
	Path    string
	Main    bool
	Version string
	Replace *listModule
	InGoMod bool
}

func (s *syncer) listModules(conf *config.Config) (map[string]listModule, error) {
	root, err := please.RepoRoot(conf.GetPlzPath())
	if err != nil {
		return nil, fmt.Errorf("get repo root: %w", err)
	}

	// Note: we can't build the modfile target and use the output dir, as we also need the go.sum for
	// the `go list` command.  We're assuming that nobody is actually generating their go.mod, and
	// that the target is always just exporting it.
	modDir := filepath.Join(root, labels.Parse(s.plzConf.ModFile()).Package)
	modFile := filepath.Join(modDir, "go.mod")

	bs, err := os.ReadFile(modFile)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	f, err := modfile.Parse(modFile, bs, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	inGoMod := map[string]bool{}
	for _, r := range f.Require {
		inGoMod[r.Mod.Path] = true
	}

	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = modDir
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("get stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start `go list`: %w", err)
	}

	modules := map[string]listModule{}
	var eg errgroup.Group
	eg.Go(func() error {
		d := json.NewDecoder(stdout)
		for {
			var m listModule
			if err := d.Decode(&m); err != nil {
				if err == io.EOF {
					return nil
				}
				return fmt.Errorf("decode module json: %w", err)
			}
			if !m.Main {
				m.InGoMod = inGoMod[m.Path]
				modules[m.Path] = m
			}
		}
	})

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("wait for `go list`: %w", err)
	}

	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("wait for decoder: %w", err)
	}

	return modules, nil
}

func (s *syncer) syncModFile(conf *config.Config, file *build.File, existingRules map[string]existingRule) error {
	modules, err := s.listModules(conf)
	if err != nil {
		return fmt.Errorf("list modules: %w", err)
	}

	// Remove "go_replace_directive" label from any rules which lack a replace directive
	for modPath, rule := range existingRules {
		m, ok := modules[modPath]
		if !ok {
			rule.removeFromFile(file)
			continue
		}

		// Remove the replace label if not needed
		if m.Replace == nil {
			err := edit.RemoveLabel(rule.versionedRule(), ReplaceLabel)
			if err != nil {
				log.Warningf("Failed to remove replace label from %v: %v", modPath, err)
			}
		}
	}

	// Make sure all modules are present in the BUILD file
	for _, m := range modules {
		// Existing rule will point to the go_mod_download with the version on it so we should use the original path
		rule, ok := existingRules[m.Path]
		if ok {
			if m.Replace != nil && m.Replace.Path != m.Path && rule.downloadRule == nil {
				// Looks like we've added in a replace directive for this module which changes the path, so we need to
				// delete the old go_repo rule and regenerate it with a go_mod_download and a go_repo.
				rule.removeFromFile(file)
			} else {
				s.syncExistingRule(rule.versionedRule(), m)
				// No other changes needed
				continue
			}
		}

		// Add a new rule to the build file if one does not exist
		if err = s.addNewRule(file, m); err != nil {
			return fmt.Errorf("failed to add new rule %v: %v", m.Path, err)
		}
	}

	return nil
}

func (s *syncer) syncExistingRule(rule *build.Rule, m listModule) {
	reqVersion := m.Version
	// Add label for the replace directive
	if m.Replace != nil {
		err := edit.AddLabel(rule, ReplaceLabel)
		if err != nil {
			log.Warningf("Failed to add replace label to %v: %v", m.Path, err)
		}
		// Update the requested version
		reqVersion = m.Replace.Version
	}
	if m.Replace == nil || m.InGoMod || s.updateTransitive {
		// Make sure the version is up-to-date
		rule.SetAttr("version", edit.NewStringExpr(reqVersion))
	}
}

func (s *syncer) addNewRule(file *build.File, m listModule) error {
	// List licences
	ls, err := s.licences.Get(m.Path, m.Version)
	if err != nil {
		return fmt.Errorf("failed to get licences for %v: %v", m.Path, err)
	}

	// If no replace directive, add a simple rule
	if m.Replace == nil {
		file.Stmt = append(file.Stmt, edit.NewGoRepoRule(m.Path, m.Version, "", ls, []string{}))
		return nil
	}

	// If replace directive is just replacing the version, add a simple rule
	if m.Replace.Path == m.Path {
		file.Stmt = append(file.Stmt, edit.NewGoRepoRule(m.Path, m.Replace.Version, "", ls, []string{ReplaceLabel}))
		return nil
	}

	dl, dlName := edit.NewModDownloadRule(m.Replace.Path, m.Replace.Version, ls)
	file.Stmt = append(file.Stmt, dl)
	file.Stmt = append(file.Stmt, edit.NewGoRepoRule(m.Path, "", dlName, nil, []string{ReplaceLabel}))
	return nil
}

type existingRule struct {
	mainRule, downloadRule *build.Rule
}

// versionedRule returns the rule which has the version on it.
func (er existingRule) versionedRule() *build.Rule {
	if er.downloadRule != nil {
		return er.downloadRule
	}
	return er.mainRule
}

// versionedRule returns the rule which has the version on it.
func (er existingRule) removeFromFile(file *build.File) {
	edit.RemoveTarget(file, er.mainRule)
	if er.downloadRule != nil {
		edit.RemoveTarget(file, er.downloadRule)
	}
}

func (s *syncer) readModules(file *build.File) (map[string]existingRule, error) {
	// existingRules contains the rules for modules. These are synced to the go.mod's version as necessary.
	existingRules := make(map[string]existingRule)
	for _, repoRule := range append(file.Rules("go_repo"), file.Rules("go_module")...) {
		if repoRule.AttrString("version") != "" {
			existingRules[repoRule.AttrString("module")] = existingRule{mainRule: repoRule}
		} else {
			// If we're using a go_mod_download for this module, then find the download rule instead.
			t := labels.ParseRelative(repoRule.AttrString("download"), file.Pkg)
			f, err := s.graph.LoadFile(t.Package)
			if err != nil {
				return nil, err
			}
			existingRules[repoRule.AttrString("module")] = existingRule{
				mainRule:     repoRule,
				downloadRule: edit.FindTargetByName(f, t.Target),
			}
		}
	}

	return existingRules, nil
}
