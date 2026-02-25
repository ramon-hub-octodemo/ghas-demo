package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// ---- Contains() tests ----

func TestContains_Found(t *testing.T) {
	haystack := []string{"alice", "bob", "carol"}
	if !Contains("bob", &haystack) {
		t.Error("expected Contains to return true for 'bob'")
	}
}

func TestContains_NotFound(t *testing.T) {
	haystack := []string{"alice", "bob", "carol"}
	if Contains("dave", &haystack) {
		t.Error("expected Contains to return false for 'dave'")
	}
}

func TestContains_EmptyHaystack(t *testing.T) {
	haystack := []string{}
	if Contains("anything", &haystack) {
		t.Error("expected Contains to return false for empty haystack")
	}
}

// ---- ProfileHeader.String() tests ----

func TestProfileHeader_String(t *testing.T) {
	cases := []struct {
		header   ProfileHeader
		expected string
	}{
		{GitHubLoginHeader, "X-GitHub-Login"},
		{GitHubNameHeader, "X-GitHub-Name"},
		{GitHubEmailHeader, "X-GitHub-Email"},
	}
	for _, c := range cases {
		if got := c.header.String(); got != c.expected {
			t.Errorf("ProfileHeader.String() = %q, want %q", got, c.expected)
		}
	}
}

// ---- LoadConfiguration() tests ----

func TestLoadConfiguration_ValidFile(t *testing.T) {
	content := `{
		"host": "127.0.0.1",
		"port": 8080,
		"database": "gallery.db",
		"secret": "testsecret",
		"allowed-origins": ["http://localhost:3000"]
	}`
	f, err := os.CreateTemp("", "config*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := LoadConfiguration(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want %q", cfg.Host, "127.0.0.1")
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Secret != "testsecret" {
		t.Errorf("Secret = %q, want %q", cfg.Secret, "testsecret")
	}
	if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != "http://localhost:3000" {
		t.Errorf("AllowedOrigins = %v, want [http://localhost:3000]", cfg.AllowedOrigins)
	}
}

func TestLoadConfiguration_FileNotFound(t *testing.T) {
	_, err := LoadConfiguration("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestLoadConfiguration_InvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "config*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("not valid json{{")
	f.Close()

	_, err = LoadConfiguration(f.Name())
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ---- OctoClaims.Valid() tests ----

func TestOctoClaims_Valid_ValidIssuer(t *testing.T) {
	claims := OctoClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "OctoGallery",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	if err := claims.Valid(); err != nil {
		t.Errorf("expected no error for valid claims, got: %v", err)
	}
}

func TestOctoClaims_Valid_InvalidIssuer(t *testing.T) {
	claims := OctoClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "WrongIssuer",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	err := claims.Valid()
	if err == nil {
		t.Error("expected error for invalid issuer, got nil")
	}
	vErr, ok := err.(*jwt.ValidationError)
	if !ok {
		t.Fatalf("expected *jwt.ValidationError, got %T", err)
	}
	if vErr.Errors&jwt.ValidationErrorIssuer == 0 {
		t.Error("expected ValidationErrorIssuer flag to be set")
	}
}

func TestOctoClaims_Valid_Expired(t *testing.T) {
	claims := OctoClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "OctoGallery",
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		},
	}
	if err := claims.Valid(); err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

// ---- HomeLinkHandler test ----

func TestHomeLinkHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	HomeLinkHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Welcome home!") {
		t.Errorf("unexpected body: %q", rr.Body.String())
	}
}

// ---- GetProfile() tests ----

func TestGetProfile(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-GitHub-Login", "testuser")
	req.Header.Set("X-GitHub-Name", "Test User")
	req.Header.Set("X-GitHub-Email", "test@example.com")

	profile := GetProfile(req)
	if profile.Login != "testuser" {
		t.Errorf("Login = %q, want %q", profile.Login, "testuser")
	}
	if profile.Name != "Test User" {
		t.Errorf("Name = %q, want %q", profile.Name, "Test User")
	}
	if profile.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", profile.Email, "test@example.com")
	}
}

func TestGetProfile_EmptyHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	profile := GetProfile(req)
	if profile.Login != "" || profile.Name != "" || profile.Email != "" {
		t.Error("expected empty profile for request without profile headers")
	}
}

// ---- GalleryHandler method routing tests ----

func TestGalleryHandler_MethodNotAllowed(t *testing.T) {
	// Initialise in-memory DB so handlers don't crash
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/gallery", nil)
	rr := httptest.NewRecorder()
	GalleryHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for disallowed method, got %d", rr.Code)
	}
}

func TestGalleryHandler_Options(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodOptions, "/gallery", nil)
	rr := httptest.NewRecorder()
	GalleryHandler(rr, req)
	// OPTIONS returns early with 200 (default recorder status)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", rr.Code)
	}
}

// ---- Gallery and ArtPiece DB operations ----

func setupTestDB(t *testing.T) {
	t.Helper()
	f, err := os.CreateTemp("", "test*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	configuration = &Configuration{
		Database:       f.Name(),
		Secret:         "testsecret",
		AllowedOrigins: []string{},
	}
	db = nil // reset cached DB
	InitializeDb()
}

func makeJWTToken(t *testing.T, login, name, email string) string {
	t.Helper()
	claims := OctoClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "OctoGallery",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Profile: OctoProfile{
			Login: login,
			Name:  name,
			Email: email,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("testsecret"))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestGetGalleryHandler_CreatesGallery(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/gallery", nil)
	req.Header.Set("X-GitHub-Login", "testuser")
	rr := httptest.NewRecorder()

	GetGalleryHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var g Gallery
	if err := json.NewDecoder(rr.Body).Decode(&g); err != nil {
		t.Fatal(err)
	}
	if g.ID <= 0 {
		t.Errorf("expected valid gallery ID, got %d", g.ID)
	}
}

func TestAddGalleryArtHandler_InvalidBody(t *testing.T) {
	setupTestDB(t)

	body := strings.NewReader("not json")
	req := httptest.NewRequest(http.MethodPost, "/gallery/art", body)
	req.Header.Set("X-GitHub-Login", "testuser")
	rr := httptest.NewRecorder()

	AddGalleryArtHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad body, got %d", rr.Code)
	}
}

func TestAddAndGetArtPiece(t *testing.T) {
	setupTestDB(t)

	// First ensure a gallery exists
	req := httptest.NewRequest(http.MethodGet, "/gallery", nil)
	req.Header.Set("X-GitHub-Login", "testuser")
	rr := httptest.NewRecorder()
	GetGalleryHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("gallery setup failed: %d", rr.Code)
	}

	artJSON := `{"title":"My Art","description":"A painting","uri":"https://example.com/art.png"}`
	req2 := httptest.NewRequest(http.MethodPost, "/gallery/art", strings.NewReader(artJSON))
	req2.Header.Set("X-GitHub-Login", "testuser")
	rr2 := httptest.NewRecorder()
	AddGalleryArtHandler(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 adding art, got %d: %s", rr2.Code, rr2.Body.String())
	}

	// Get all art pieces
	req3 := httptest.NewRequest(http.MethodGet, "/gallery/art", nil)
	req3.Header.Set("X-GitHub-Login", "testuser")
	rr3 := httptest.NewRecorder()
	GetGalleryAllArtHandler(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("expected 200 getting art, got %d: %s", rr3.Code, rr3.Body.String())
	}
	var pieces []ArtPiece
	if err := json.NewDecoder(rr3.Body).Decode(&pieces); err != nil {
		t.Fatal(err)
	}
	if len(pieces) != 1 {
		t.Fatalf("expected 1 art piece, got %d", len(pieces))
	}
	if pieces[0].Title != "My Art" {
		t.Errorf("Title = %q, want %q", pieces[0].Title, "My Art")
	}
}

func TestGalleryArtsHandler_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/gallery/art", nil)
	rr := httptest.NewRecorder()
	GalleryArtsHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for disallowed method, got %d", rr.Code)
	}
}

func TestGalleryArtHandler_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPatch, "/gallery/art/1", nil)
	rr := httptest.NewRecorder()
	GalleryArtHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for disallowed method, got %d", rr.Code)
	}
}
