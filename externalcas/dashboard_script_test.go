package externalcas

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboardScriptSyntax checks the embedded dashboard JS parses. A
// broken <script> block renders the page blank, and no other test catches it.
//
// The check shells out to node --check when node is available (dev boxes,
// CI images with node); otherwise it falls back to a bracket-balance scan,
// which catches the common fatal cases (unclosed try/brace) without a full
// JS parser.
func TestDashboardScriptSyntax(t *testing.T) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}
	s := string(b)
	i := strings.Index(s, "<script>")
	j := strings.Index(s, "</script>")
	if i < 0 || j < 0 || j <= i {
		t.Fatal("no <script> block found in dashboard page")
	}
	js := s[i+len("<script>") : j]
	if len(js) < 1000 {
		t.Fatalf("dashboard script suspiciously small: %d bytes", len(js))
	}

	if node, err := exec.LookPath("node"); err == nil {
		dir := t.TempDir()
		file := filepath.Join(dir, "dash.js")
		if err := os.WriteFile(file, []byte(js), 0o600); err != nil {
			t.Fatalf("write temp script: %v", err)
		}
		out, err := exec.Command(node, "--check", file).CombinedOutput()
		if err != nil {
			t.Fatalf("dashboard script has a syntax error (page would render blank): %v\n%s", err, out)
		}
		return
	}

	// Fallback: bracket balance ignoring string literals and comments.
	depth := 0
	var stack []byte
	inS, inD, inT := false, false, false // ' " `
	inLC, inBC := false, false           // /* */ //
	for k := 0; k < len(js); k++ {
		c := js[k]
		switch {
		case inLC:
			if c == '\n' {
				inLC = false
			}
		case inBC:
			if c == '*' && k+1 < len(js) && js[k+1] == '/' {
				inBC = false
				k++
			}
		case inS || inD || inT:
			if c == '\\' {
				k++
			} else if (inS && c == '\'') || (inD && c == '"') || (inT && c == '`') {
				inS, inD, inT = false, false, false
			}
		default:
			switch c {
			case '\'':
				inS = true
			case '"':
				inD = true
			case '`':
				inT = true
			case '/':
				if k+1 < len(js) && js[k+1] == '/' {
					inLC = true
					k++
				} else if k+1 < len(js) && js[k+1] == '*' {
					inBC = true
					k++
				}
			case '{', '(', '[':
				stack = append(stack, c)
				depth++
			case '}', ')', ']':
				if len(stack) == 0 {
					t.Fatalf("dashboard script: unmatched %q at offset %d", c, k)
				}
				open := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				depth--
				want := map[byte]byte{'}': '{', ')': '(', ']': '['}[c]
				if open != want {
					t.Fatalf("dashboard script: %q closes %q at offset %d", c, open, k)
				}
			}
		}
	}
	if inS || inD || inT {
		t.Fatal("dashboard script: unterminated string literal")
	}
	if len(stack) != 0 {
		t.Fatalf("dashboard script: %d unclosed %q at end of script", len(stack), stack[len(stack)-1])
	}
}
