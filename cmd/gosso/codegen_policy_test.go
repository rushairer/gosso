package gosso

import (
	"testing"

	"github.com/rushairer/gouno/generator"
	"github.com/spf13/cobra"
)

func TestProjectCodegenIsAbsentWithoutManifest(t *testing.T) {
	projectRoot := t.TempDir()

	projectCmd, err := generator.LoadProjectCommand(projectRoot)
	if err != nil {
		t.Fatalf("load project command: %v", err)
	}
	if projectCmd != nil {
		t.Fatalf("unexpected project Codegen command %q without .gouno/codegen.yaml", projectCmd.Name())
	}

	root := &cobra.Command{Use: "gosso-test"}
	attached, err := generator.AttachProjectCommand(root, projectRoot)
	if err != nil {
		t.Fatalf("attach project command: %v", err)
	}
	if attached {
		t.Fatal("project Codegen command attached without manifest")
	}
	assertNoLegacyCodegenCommand(t, root)
}

func TestRootCommandDoesNotRegisterLegacyCodegenStatically(t *testing.T) {
	assertNoLegacyCodegenCommand(t, rootCmd)
}

func assertNoLegacyCodegenCommand(t *testing.T, root *cobra.Command) {
	t.Helper()
	for _, cmd := range root.Commands() {
		if cmd.Name() == "gen" || cmd.Name() == "generator" {
			t.Fatalf("unexpected legacy Codegen command %q", cmd.Name())
		}
	}
}
