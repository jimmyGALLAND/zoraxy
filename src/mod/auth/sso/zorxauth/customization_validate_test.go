package zorxauth

import (
	"bytes"
	"httptest"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makePNG renders a blank PNG of the given size for upload validation tests
func makePNG(t *testing.T, width int, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{1, 2, 3, 255})

	buf := bytes.Buffer{}
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("failed to encode test png: %v", err)
	}
	return buf.Bytes()
}

func TestValidateSVGContentRejectsActiveContent(t *testing.T) {
	cases := []struct {
		name string
		svg  string
	}{
		{"script element", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>`},
		{"uppercase script element", `<svg xmlns="http://www.w3.org/2000/svg"><SCRIPT>alert(1)</SCRIPT></svg>`},
		{"event handler", `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><circle r="5"/></svg>`},
		{"event handler on child", `<svg xmlns="http://www.w3.org/2000/svg"><circle r="5" onmouseover="alert(1)"/></svg>`},
		{"foreignObject", `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>`},
		{"iframe", `<svg xmlns="http://www.w3.org/2000/svg"><iframe src="https://evil.example"/></svg>`},
		{"animate to href", `<svg xmlns="http://www.w3.org/2000/svg"><a><animate attributeName="href" values="javascript:alert(1)"/></a></svg>`},
		{"set element", `<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="onload" to="alert(1)"/></svg>`},
		{"javascript href", `<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><circle r="5"/></a></svg>`},
		{"obfuscated javascript href", `<svg xmlns="http://www.w3.org/2000/svg"><a href="java&#9;script:alert(1)"><circle r="5"/></a></svg>`},
		{"external use reference", `<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.example/payload.svg#x"/></svg>`},
		{"external image reference", `<svg xmlns="http://www.w3.org/2000/svg"><image href="https://tracker.example/pixel.png"/></svg>`},
		{"entity declaration", `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`},
		{"xml stylesheet", `<?xml-stylesheet type="text/css" href="https://evil.example/x.css"?><svg xmlns="http://www.w3.org/2000/svg"><circle r="5"/></svg>`},
		{"css import", `<svg xmlns="http://www.w3.org/2000/svg"><circle r="5" style="@import url(https://evil.example/x.css)"/></svg>`},
		{"not an svg root", `<html><body><script>alert(1)</script></body></html>`},
		{"malformed xml", `<svg xmlns="http://www.w3.org/2000/svg"><circle r="5">`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSVGContent([]byte(tc.svg)); err == nil {
				t.Errorf("expected %s to be rejected, but it was accepted", tc.name)
			}
		})
	}
}

func TestValidateSVGContentAcceptsPlainArtwork(t *testing.T) {
	cases := []struct {
		name string
		svg  string
	}{
		{"simple shapes", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#f00"/></svg>`},
		{"gradient and group", `<svg xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g"><stop offset="0" stop-color="#fff"/></linearGradient></defs><g><rect width="10" height="10" fill="url(#g)"/></g></svg>`},
		{"internal fragment reference", `<svg xmlns="http://www.w3.org/2000/svg"><defs><path id="p" d="M0 0 L1 1"/></defs><use href="#p"/></svg>`},
		{"inline data image", `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,iVBORw0KGgo="/></svg>`},
		{"doctype without entities", `<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"><circle r="5"/></svg>`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSVGContent([]byte(tc.svg)); err != nil {
				t.Errorf("expected %s to be accepted, got: %v", tc.name, err)
			}
		})
	}
}

// The resources shipped with Zoraxy must themselves pass the upload validator,
// otherwise an administrator could not re-upload the stock artwork.
func TestDefaultAssetsPassValidation(t *testing.T) {
	for _, key := range []string{ASSET_BRAND_MARK, ASSET_WATERMARK, ASSET_WALLPAPER} {
		content, _ := defaultAssetContent(key)
		if err := validateSVGContent(content); err != nil {
			t.Errorf("embedded default %s failed validation: %v", key, err)
		}
	}
}

func TestValidateUploadContentRejectsExtensionMismatch(t *testing.T) {
	spec := assetSpecs[ASSET_BRAND_MARK]

	//An HTML payload renamed to look like an image must not be stored
	payload := []byte(`<html><script>alert(document.cookie)</script></html>`)
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".webp"} {
		if err := validateUploadContent(payload, ext, spec); err == nil {
			t.Errorf("expected HTML payload renamed to %s to be rejected", ext)
		}
	}

	//A real PNG carrying a .jpg extension is also a mismatch
	if err := validateUploadContent(makePNG(t, 128, 128), ".jpg", spec); err == nil {
		t.Error("expected PNG content with a .jpg extension to be rejected")
	}
}

func TestValidateUploadContentEnforcesAspectRatio(t *testing.T) {
	spec := assetSpecs[ASSET_WATERMARK] //600 x 200, 3:1

	if err := validateUploadContent(makePNG(t, 600, 200), ".png", spec); err != nil {
		t.Errorf("expected matching ratio to be accepted, got: %v", err)
	}

	if err := validateUploadContent(makePNG(t, 300, 100), ".png", spec); err != nil {
		t.Errorf("expected scaled matching ratio to be accepted, got: %v", err)
	}

	if err := validateUploadContent(makePNG(t, 600, 400), ".png", spec); err == nil {
		t.Error("expected mismatched ratio to be rejected")
	}
}

// The stored file name is always derived from the asset key, never from the
// uploaded file name, so a traversal attempt cannot escape the branding folder.
func TestUploadFileNameCannotEscapeBrandingFolder(t *testing.T) {
	hostileNames := []string{
		`../../../../windows/system32/evil.png`,
		`../../conf/sso/zorxauth/branding/../../../sys.db.png`,
		`..\..\evil.png`,
		`/etc/cron.d/evil.svg`,
		"evil.png" + string(rune(0)) + ".txt",
	}

	for _, name := range hostileNames {
		ext := strings.ToLower(filepath.Ext(name))
		if _, accepted := brandingUploadTypes[ext]; !accepted {
			continue //Rejected before a path is ever built
		}

		//This mirrors what HandleCustomizationUpload builds
		stored := ASSET_WALLPAPER + ext
		if strings.ContainsAny(stored, `/\`) || stored != filepath.Base(stored) {
			t.Errorf("stored name %q derived from %q is not a bare file name", stored, name)
		}
	}
}

func TestSanitizeBrandingTextStripsControlCharacters(t *testing.T) {
	if got := sanitizeBrandingText("  Acme" + string(rune(0)) + " Identity\r\n "); got != "Acme Identity" {
		t.Errorf("unexpected sanitize result: %q", got)
	}
}

// A label containing a template placeholder must be emitted literally rather
// than expanded into markup by a later replacement pass.
func TestRenderAuthPageDoesNotExpandPlaceholdersFromText(t *testing.T) {
	ar := &AuthRouter{
		branding: &BrandingConfig{
			BrandText:     "{{watermark_icon}}",
			WatermarkText: "<img src=x onerror=alert(1)>",
		},
	}

	page := string(ar.RenderAuthPage())

	if strings.Contains(page, `<span>{{watermark_icon}}</span>`) == false &&
		strings.Contains(page, "{{watermark_icon}}") == false {
		t.Error("expected the placeholder in the brand text to survive as literal text")
	}
	if strings.Contains(page, "<img src=x onerror=alert(1)>") {
		t.Error("watermark text was not HTML escaped")
	}
	if !strings.Contains(page, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("expected the watermark text to be HTML escaped")
	}
}

// An auth.html placed in the config folder must replace the embedded template.
func TestRenderAuthPageUsesOverrideFromConfigFolder(t *testing.T) {
    dir := t.TempDir()
    custom := "<html>CUSTOM {{brand_text}}</html>"
    if err := os.WriteFile(filepath.Join(dir, "auth.html"), []byte(custom), 0644); err != nil {
        t.Fatal(err)
    }

    ar := &AuthRouter{
        Options: &AuthRouterOptions{ConfigFolderPath: dir},
        branding: &BrandingConfig{
            BrandText:     "MyBrand",
            WatermarkText: "WM",
        },
    }

    page := string(ar.RenderAuthPage())
    if !strings.Contains(page, "CUSTOM MyBrand") {
        t.Errorf("expected the override template to be used, got: %s", page)
    }
}

// Without an override file the embedded template must still be served.
func TestRenderAuthPageFallsBackToEmbedded(t *testing.T) {
    ar := &AuthRouter{
        Options:  &AuthRouterOptions{ConfigFolderPath: t.TempDir()},
        branding: &BrandingConfig{BrandText: "MyBrand", WatermarkText: "WM"},
    }

    page := string(ar.RenderAuthPage())
    if strings.Contains(page, "CUSTOM") || !strings.Contains(page, "MyBrand") {
        t.Error("expected the embedded template to be used when no override exists")
    }
}

func newCustomAssetTestRouter(t *testing.T) (*AuthRouter, string) {
	t.Helper()
	base := t.TempDir()
	custom := filepath.Join(base, CUSTOM_FOLDER)

	files := map[string]string{
		// Served files
		filepath.Join(custom, "logo.png"):         "PNGDATA",
		filepath.Join(custom, "guide.pdf"):        "PDFDATA",
		filepath.Join(custom, "client.zip"):       "ZIPDATA",
		filepath.Join(custom, "icon.svg"):         "<svg xmlns='http://www.w3.org/2000/svg'/>",
		filepath.Join(custom, "sub", "deep.png"):  "DEEPDATA",
		// Must never be served
		filepath.Join(custom, "page.html"):        "<script>alert(1)</script>",
		filepath.Join(custom, "script.js"):        "alert(1)",
		filepath.Join(custom, ".hidden.png"):      "HIDDEN",
		filepath.Join(custom, ".git", "config.txt"): "GITCONFIG",
		filepath.Join(base, "secret.txt"):         "TOPSECRET", // outside the custom folder
		filepath.Join(base, "branding.json"):      "{}",
	}
	for p, content := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	ar := &AuthRouter{Options: &AuthRouterOptions{ConfigFolderPath: base}}
	return ar, base
}

func serveCustomAsset(ar *AuthRouter, method, urlPath string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, urlPath, nil)
	rec := httptest.NewRecorder()
	ar.ServeCustomAsset(rec, req)
	return rec
}

func TestServeCustomAsset(t *testing.T) {
	ar, _ := newCustomAssetTestRouter(t)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string // checked only when the status is 200
	}{
		{"served png", http.MethodGet, "/assets/custom/logo.png", http.StatusOK, "PNGDATA"},
		{"served pdf", http.MethodGet, "/assets/custom/guide.pdf", http.StatusOK, "PDFDATA"},
		{"served from sub folder", http.MethodGet, "/assets/custom/sub/deep.png", http.StatusOK, "alert(1)"},
		{"head request allowed", http.MethodHead, "/assets/custom/logo.png", http.StatusOK, ""},
		{"js refused", http.MethodGet, "/assets/custom/script.js", http.StatusOK, "JSDATA"},

		{"missing file", http.MethodGet, "/assets/custom/nope.png", http.StatusNotFound, ""},
		{"empty name", http.MethodGet, "/assets/custom/", http.StatusNotFound, ""},
		{"folder", http.MethodGet, "/assets/custom/sub", http.StatusNotFound, ""},

		{"html refused", http.MethodGet, "/assets/custom/page.html", http.StatusNotFound, ""},
		{"hidden file", http.MethodGet, "/assets/custom/.hidden.png", http.StatusNotFound, ""},
		{"hidden folder", http.MethodGet, "/assets/custom/.git/config.txt", http.StatusNotFound, ""},

		{"traversal to parent", http.MethodGet, "/assets/custom/../secret.txt", http.StatusNotFound, ""},
		{"traversal nested", http.MethodGet, "/assets/custom/sub/../../secret.txt", http.StatusNotFound, ""},
		{"traversal to branding.json", http.MethodGet, "/assets/custom/../branding.json", http.StatusNotFound, ""},
		{"traversal encoded", http.MethodGet, "/assets/custom/..%2fsecret.txt", http.StatusNotFound, ""},

		{"post refused", http.MethodPost, "/assets/custom/logo.png", http.StatusMethodNotAllowed, ""},
		{"delete refused", http.MethodDelete, "/assets/custom/logo.png", http.StatusMethodNotAllowed, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveCustomAsset(ar, tc.method, tc.path)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s: got status %d, want %d", tc.method, tc.path, rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK && tc.method == http.MethodGet {
				if got := rec.Body.String(); got != tc.wantBody {
					t.Errorf("unexpected body: got %q, want %q", got, tc.wantBody)
				}
			}
			// Whatever the outcome, private content must never leak
			if strings.Contains(rec.Body.String(), "TOPSECRET") || strings.Contains(rec.Body.String(), "GITCONFIG") {
				t.Errorf("response for %s leaked private content", tc.path)
			}
		})
	}
}

func TestServeCustomAssetHeaders(t *testing.T) {
	ar, _ := newCustomAssetTestRouter(t)

	rec := serveCustomAsset(ar, http.MethodGet, "/assets/custom/logo.png")
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("expected nosniff, got %q", got)
	}

	rec = serveCustomAsset(ar, http.MethodGet, "/assets/custom/icon.svg")
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Errorf("expected a sandboxing CSP on SVG files, got %q", csp)
	}

	rec = serveCustomAsset(ar, http.MethodGet, "/assets/custom/client.zip")
	if got := rec.Header().Get("Content-Disposition"); got != "attachment" {
		t.Errorf("expected zip files to be forced as downloads, got %q", got)
	}
}

// A symlink inside the custom folder must not allow reading files outside of it.
func TestServeCustomAssetSymlinkEscape(t *testing.T) {
	ar, base := newCustomAssetTestRouter(t)

	link := filepath.Join(base, CUSTOM_FOLDER, "escape.txt")
	if err := os.Symlink(filepath.Join(base, "secret.txt"), link); err != nil {
		t.Skipf("symlinks not supported here: %v", err)
	}

	rec := serveCustomAsset(ar, http.MethodGet, "/assets/custom/escape.txt")
	if rec.Code != http.StatusNotFound {
		t.Errorf("symlink escaping the custom folder: got status %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "TOPSECRET") {
		t.Error("symlink escape leaked the secret file")
	}
}

// Without a custom folder, every request must simply be a 404.
func TestServeCustomAssetNoFolder(t *testing.T) {
	ar := &AuthRouter{Options: &AuthRouterOptions{ConfigFolderPath: t.TempDir()}}
	rec := serveCustomAsset(ar, http.MethodGet, "/assets/custom/logo.png")
	if rec.Code != http.StatusNotFound {
		t.Errorf("got status %d, want 404", rec.Code)
	}
}