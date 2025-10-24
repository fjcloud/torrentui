package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/storage"
	"github.com/anacrolix/torrent/types/infohash"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

//go:embed static/*
var staticFiles embed.FS

// Config holds application configuration
type Config struct {
	ListenAddr          string
	DownloadDir         string
	SessionDir          string
	MaxUploadRateKBPS   int64
	MaxDownloadRateKBPS int64
	Username            string
	PasswordHash        string
	SessionTimeout      time.Duration
	SecureCookie        bool
	TorrentListenPort   int
	PublicIP            string
}

// Torrent represents a torrent in the API
type Torrent struct {
	InfoHash     string    `json:"infoHash"`
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	Progress     float64   `json:"progress"`
	Size         int64     `json:"size"`
	Downloaded   int64     `json:"downloaded"`
	DownloadRate int64     `json:"downloadRate"`
	UploadRate   int64     `json:"uploadRate"`
	Peers        int       `json:"peers"`
	AddedAt      time.Time `json:"addedAt"`
	SavePath     string    `json:"savePath"`
	Seeding      bool      `json:"seeding"`
	SeededBytes  int64     `json:"seededBytes"`
	SeedTime     int64     `json:"seedTime"`
}

// TorrentFile represents a file within a torrent
type TorrentFile struct {
	Path           string  `json:"path"`
	Length         int64   `json:"length"`
	BytesCompleted int64   `json:"bytesCompleted"`
	Progress       float64 `json:"progress"`
	Priority       string  `json:"priority"`
	MimeType       string  `json:"mimeType"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// Session represents an authenticated session
type Session struct {
	Token     string
	ExpiresAt time.Time
}

// Server holds the application state
type Server struct {
	config         *Config
	client         *torrent.Client
	seedStartTimes map[string]time.Time // Track when seeding started for each torrent
	sessions       map[string]*Session  // Active sessions
	sessionsMux    sync.RWMutex
	loginLimiters  map[string]*rate.Limiter // Rate limiters per IP
	limitersMux    sync.RWMutex
}

// NewServer creates a new server instance
func NewServer(config *Config) (*Server, error) {
	// Create directories
	if err := os.MkdirAll(config.DownloadDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create download directory: %w", err)
	}
	if err := os.MkdirAll(config.SessionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	// Configure torrent client
	clientConfig := torrent.NewDefaultClientConfig()
	clientConfig.DataDir = config.DownloadDir

	// Disable piece completion database to prevent "already complete" issues
	clientConfig.DisableAcceptRateLimiting = false
	clientConfig.DefaultStorage = storage.NewFile(config.DownloadDir)

	// Enable seeding and peer connections
	clientConfig.NoUpload = false
	clientConfig.DisableTrackers = false
	clientConfig.DisableWebseeds = false
	clientConfig.DisableWebtorrent = false
	clientConfig.DisablePEX = false
	clientConfig.Seed = true

	// Configure listening port for incoming connections (seeding)
	if config.TorrentListenPort > 0 {
		clientConfig.ListenPort = config.TorrentListenPort
		clientConfig.DisableIPv6 = false
		log.Printf("Torrent client listening on port %d for incoming connections", config.TorrentListenPort)
	}

	// Set public IP if configured (helps with seeding)
	if config.PublicIP != "" {
		clientConfig.PublicIp4 = net.ParseIP(config.PublicIP)
		if clientConfig.PublicIp4 != nil {
			log.Printf("Using public IP: %s", config.PublicIP)
		} else {
			log.Printf("⚠️  Invalid PUBLIC_IP format: %s", config.PublicIP)
		}
	}

	// Set rate limits if configured
	if config.MaxUploadRateKBPS > 0 {
		clientConfig.UploadRateLimiter = rate.NewLimiter(rate.Limit(config.MaxUploadRateKBPS*1024), int(config.MaxUploadRateKBPS*1024))
	}
	if config.MaxDownloadRateKBPS > 0 {
		clientConfig.DownloadRateLimiter = rate.NewLimiter(rate.Limit(config.MaxDownloadRateKBPS*1024), int(config.MaxDownloadRateKBPS*1024))
	}

	// Create torrent client
	client, err := torrent.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create torrent client: %w", err)
	}

	return &Server{
		config:         config,
		client:         client,
		seedStartTimes: make(map[string]time.Time),
		sessions:       make(map[string]*Session),
		loginLimiters:  make(map[string]*rate.Limiter),
	}, nil
}

// Close gracefully shuts down the server
func (s *Server) Close() error {
	s.client.Close()
	return nil
}

// getTorrentStatus returns the status string for a torrent
func getTorrentStatus(t *torrent.Torrent) string {
	if t == nil {
		return "stopped"
	}

	// Check if torrent is closed
	select {
	case <-t.Closed():
		return "stopped"
	default:
	}

	// Check if torrent is seeding
	if t.Seeding() {
		return "seeding"
	}

	// Check if torrent is downloading by comparing completed vs total
	totalLength := t.Length()
	completed := t.BytesCompleted()

	if totalLength > 0 && completed < totalLength {
		return "downloading"
	}

	// If completed equals total length, it's seeding
	if totalLength > 0 && completed >= totalLength {
		return "seeding"
	}

	return "paused"
}

// torrentToAPI converts a torrent.Torrent to our API Torrent struct
func (s *Server) torrentToAPI(t *torrent.Torrent) Torrent {
	if t == nil {
		return Torrent{}
	}

	info := t.Info()
	stats := t.Stats()
	infoHash := t.InfoHash().HexString()

	// Calculate seeding stats
	totalLength := t.Length()
	completed := t.BytesCompleted()
	isSeeding := t.Seeding() || (totalLength > 0 && completed >= totalLength)

	var seedTime int64
	if isSeeding {
		if startTime, exists := s.seedStartTimes[infoHash]; exists {
			seedTime = int64(time.Since(startTime).Seconds())
		} else {
			// If we don't have a start time, assume it started when it became complete
			s.seedStartTimes[infoHash] = time.Now()
			seedTime = 0
		}
	} else {
		// Clear start time if not seeding
		delete(s.seedStartTimes, infoHash)
	}

	return Torrent{
		InfoHash:     infoHash,
		Name:         info.Name,
		Status:       getTorrentStatus(t),
		Progress:     float64(t.BytesCompleted()) / float64(t.Length()),
		Size:         t.Length(),
		Downloaded:   t.BytesCompleted(),
		DownloadRate: stats.BytesReadUsefulData.Int64(),
		UploadRate:   stats.BytesWrittenData.Int64(),
		Peers:        t.Stats().ConnectedSeeders + t.Stats().ActivePeers,
		AddedAt:      time.Now(), // Use current time as fallback
		SavePath:     filepath.Join(s.config.DownloadDir, info.Name),
		Seeding:      isSeeding,
		SeededBytes:  stats.BytesWrittenData.Int64(),
		SeedTime:     seedTime,
	}
}

// torrentFileToAPI converts a torrent.File to our API TorrentFile struct
func torrentFileToAPI(f *torrent.File) TorrentFile {
	if f == nil {
		return TorrentFile{}
	}

	path := f.Path()
	ext := filepath.Ext(path)
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	priority := "normal"
	if f.Priority() == torrent.PiecePriorityNone {
		priority = "off"
	} else if f.Priority() == torrent.PiecePriorityHigh {
		priority = "high"
	}

	return TorrentFile{
		Path:           path,
		Length:         f.Length(),
		BytesCompleted: f.BytesCompleted(),
		Progress:       float64(f.BytesCompleted()) / float64(f.Length()),
		Priority:       priority,
		MimeType:       mimeType,
	}
}

// validateInfoHash validates that the infoHash is exactly 40 hex characters
func validateInfoHash(infoHash string) error {
	if len(infoHash) != 40 {
		return fmt.Errorf("infoHash must be exactly 40 hex characters")
	}
	for _, c := range infoHash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("infoHash must contain only lowercase hex characters")
		}
	}
	return nil
}

// validatePath validates that the path is safe and doesn't contain traversal
func validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Check for directory traversal
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return fmt.Errorf("path contains invalid characters")
	}

	// Normalize the path
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return fmt.Errorf("path is not normalized")
	}

	return nil
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, err error, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := ErrorResponse{
		Error:  err.Error(),
		Detail: detail,
	}

	json.NewEncoder(w).Encode(response)
}

// hashPassword creates a bcrypt hash of the password
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// verifyPassword checks if password matches the hash
func verifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// generateToken generates a random session token
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// createSession creates a new session for the user
func (s *Server) createSession() (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	session := &Session{
		Token:     token,
		ExpiresAt: time.Now().Add(s.config.SessionTimeout),
	}

	s.sessionsMux.Lock()
	s.sessions[token] = session
	s.sessionsMux.Unlock()

	return token, nil
}

// validateSession checks if a session token is valid
func (s *Server) validateSession(token string) bool {
	s.sessionsMux.RLock()
	defer s.sessionsMux.RUnlock()

	session, exists := s.sessions[token]
	if !exists {
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		return false
	}

	return true
}

// deleteSession removes a session
func (s *Server) deleteSession(token string) {
	s.sessionsMux.Lock()
	delete(s.sessions, token)
	s.sessionsMux.Unlock()
}

// cleanupExpiredSessions removes expired sessions
func (s *Server) cleanupExpiredSessions() {
	s.sessionsMux.Lock()
	defer s.sessionsMux.Unlock()

	now := time.Now()
	for token, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

// getLoginLimiter returns rate limiter for an IP address
func (s *Server) getLoginLimiter(ip string) *rate.Limiter {
	s.limitersMux.Lock()
	defer s.limitersMux.Unlock()

	limiter, exists := s.loginLimiters[ip]
	if !exists {
		// 5 attempts per minute (one every 12 seconds, burst of 5)
		limiter = rate.NewLimiter(rate.Every(12*time.Second), 5)
		s.loginLimiters[ip] = limiter
	}

	return limiter
}

// authMiddleware checks if the request has a valid session
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if no username is configured
		if s.config.Username == "" {
			next(w, r)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"), "")
			return
		}

		if !s.validateSession(cookie.Value) {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"), "")
			return
		}

		next(w, r)
	}
}

// handleLogin handles POST /api/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Get client IP for rate limiting (strip port)
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = strings.Split(xff, ",")[0]
		ip = strings.TrimSpace(ip)
	}
	// Strip port from IP address
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Check rate limit
	limiter := s.getLoginLimiter(ip)
	if !limiter.Allow() {
		log.Printf("Rate limit exceeded for IP: %s", ip)
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many login attempts"), "Please try again later")
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON payload"), "")
		return
	}

	// Check username
	if payload.Username != s.config.Username {
		time.Sleep(100 * time.Millisecond) // Prevent timing attacks
		log.Printf("Failed login attempt for username: %s from IP: %s", payload.Username, ip)
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials"), "")
		return
	}

	// Check password with bcrypt
	if err := verifyPassword(payload.Password, s.config.PasswordHash); err != nil {
		time.Sleep(100 * time.Millisecond) // Prevent timing attacks
		log.Printf("Failed login attempt for user: %s from IP: %s", s.config.Username, ip)
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials"), "")
		return
	}

	// Create session
	token, err := s.createSession()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to create session"), "")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.config.SessionTimeout.Seconds()),
	})

	log.Printf("Successful login for user: %s from IP: %s", s.config.Username, ip)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleLogout handles POST /api/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		s.deleteSession(cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleCheckAuth handles GET /api/auth/check
func (s *Server) handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// If no auth configured, always return true
	if s.config.Username == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"authRequired":  false,
		})
		return
	}

	cookie, err := r.Cookie("session_token")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"authRequired":  true,
		})
		return
	}

	authenticated := s.validateSession(cookie.Value)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": authenticated,
		"authRequired":  true,
	})
}

// handleHealth handles the health check endpoint
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleGetTorrents handles GET /api/torrents
func (s *Server) handleGetTorrents(w http.ResponseWriter, r *http.Request) {
	torrents := make([]Torrent, 0)
	for _, t := range s.client.Torrents() {
		torrents = append(torrents, s.torrentToAPI(t))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(torrents)
}

// handlePostTorrents handles POST /api/torrents
func (s *Server) handlePostTorrents(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Handle file upload
		file, header, err := r.FormFile("file")
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("failed to get file from form"), "")
			return
		}
		defer file.Close()

		// Limit file size to 1MB
		if header.Size > 1024*1024 {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("file too large"), "Maximum size is 1MB")
			return
		}

		// Read file content
		fileContent, err := io.ReadAll(file)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to read file"), "")
			return
		}

		// Add torrent from file content - save to temp file first
		tmpFile, err := os.CreateTemp("", "torrent_*.torrent")
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to create temp file"), "")
			return
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(fileContent); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to write temp file"), "")
			return
		}
		tmpFile.Close()

		t, err := s.client.AddTorrentFromFile(tmpFile.Name())
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid torrent file"), "")
			return
		}

		log.Printf("Added torrent: %s", t.Name())

		// Start downloading
		<-t.GotInfo()
		t.DownloadAll()

		// Allow data upload for seeding
		t.AllowDataUpload()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(s.torrentToAPI(t))
		return
	}

	// Handle JSON payload
	var payload struct {
		Magnet  string `json:"magnet"`
		FromURL string `json:"fromURL"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON payload"), "")
		return
	}

	if payload.Magnet == "" && payload.FromURL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("magnet or fromURL required"), "")
		return
	}

	var t *torrent.Torrent
	var err error

	if payload.Magnet != "" {
		// Add from magnet
		t, err = s.client.AddMagnet(payload.Magnet)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid magnet link"), "")
			return
		}
	} else {
		// Add from URL - download the torrent file first
		resp, err := http.Get(payload.FromURL)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("failed to download torrent from URL"), "")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			writeError(w, http.StatusBadRequest, fmt.Errorf("failed to download torrent from URL: %s", resp.Status), "")
			return
		}

		// Save to temp file
		tmpFile, err := os.CreateTemp("", "torrent_*.torrent")
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to create temp file"), "")
			return
		}
		defer os.Remove(tmpFile.Name())

		if _, err := io.Copy(tmpFile, resp.Body); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to write temp file"), "")
			return
		}
		tmpFile.Close()

		t, err = s.client.AddTorrentFromFile(tmpFile.Name())
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid torrent file from URL"), "")
			return
		}
	}

	// Start downloading
	<-t.GotInfo()
	t.DownloadAll()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(s.torrentToAPI(t))
}

// handleGetTorrent handles GET /api/torrents/{infoHash}
func (s *Server) handleGetTorrent(w http.ResponseWriter, r *http.Request) {
	infoHash := strings.TrimPrefix(r.URL.Path, "/api/torrents/")

	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.torrentToAPI(t))
}

// handleDeleteTorrent handles DELETE /api/torrents/{infoHash}
func (s *Server) handleDeleteTorrent(w http.ResponseWriter, r *http.Request) {
	infoHash := strings.TrimPrefix(r.URL.Path, "/api/torrents/")

	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	// Get torrent info before dropping
	info := t.Info()

	// Drop the torrent (removes from client and cleans up state)
	t.Drop()

	// Clean up seeding tracking
	delete(s.seedStartTimes, infoHash)

	// Always delete files to prevent "already complete" issue
	if info != nil {
		torrentPath := filepath.Join(s.config.DownloadDir, info.Name)
		os.RemoveAll(torrentPath)

		// Clean up cache files
		torrentFile := filepath.Join(s.config.DownloadDir, info.Name+".torrent")
		os.Remove(torrentFile)

		stateFiles := []string{
			filepath.Join(s.config.DownloadDir, "."+info.Name+".state"),
			filepath.Join(s.config.DownloadDir, info.Name+".fastresume"),
		}
		for _, f := range stateFiles {
			os.Remove(f)
		}
	}

	log.Printf("Deleted torrent: %s", infoHash)
	w.WriteHeader(http.StatusNoContent)
}

// handleGetTorrentFiles handles GET /api/torrents/{infoHash}/files
func (s *Server) handleGetTorrentFiles(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid path"), "")
		return
	}

	infoHash := pathParts[3]
	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	files := make([]TorrentFile, 0)
	for _, f := range t.Files() {
		files = append(files, torrentFileToAPI(f))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

// handleGetFile handles GET /api/torrents/{infoHash}/file
func (s *Server) handleGetFile(w http.ResponseWriter, r *http.Request) {
	s.handleFileRequest(w, r, false)
}

// handleHeadFile handles HEAD /api/torrents/{infoHash}/file
func (s *Server) handleHeadFile(w http.ResponseWriter, r *http.Request) {
	s.handleFileRequest(w, r, true)
}

// handleFileRequest handles both GET and HEAD requests for files
func (s *Server) handleFileRequest(w http.ResponseWriter, r *http.Request, headOnly bool) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid path"), "")
		return
	}

	infoHash := pathParts[3]
	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	filePath := r.URL.Query().Get("path")
	if err := validatePath(filePath); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	// Find the file
	var targetFile *torrent.File
	for _, f := range t.Files() {
		if f.Path() == filePath {
			targetFile = f
			break
		}
	}

	if targetFile == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("file not found"), "")
		return
	}

	// Check if file is available
	if targetFile.BytesCompleted() == 0 {
		writeError(w, http.StatusConflict, fmt.Errorf("file not available yet"), "not available yet")
		return
	}

	// Set content type
	ext := filepath.Ext(filePath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// Set content disposition
	disposition := r.URL.Query().Get("disposition")
	if disposition == "" {
		disposition = "attachment"
	}

	// For inline viewing of media files, use inline disposition
	if disposition == "inline" {
		if strings.HasPrefix(contentType, "image/") ||
			strings.HasPrefix(contentType, "video/") ||
			strings.HasPrefix(contentType, "audio/") ||
			strings.HasPrefix(contentType, "text/") {
			disposition = "inline"
		}
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%s", disposition, filepath.Base(filePath)))
	w.Header().Set("Accept-Ranges", "bytes")

	// Get file size
	fileSize := targetFile.Length()
	w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))

	if headOnly {
		return
	}

	// Serve the file content
	reader := targetFile.NewReader()
	defer reader.Close()

	// Support range requests
	http.ServeContent(w, r, filepath.Base(filePath), time.Now(), reader)
}

// handleDeleteFile handles DELETE /api/torrents/{infoHash}/file
func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid path"), "")
		return
	}

	infoHash := pathParts[3]
	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	filePath := r.URL.Query().Get("path")
	if err := validatePath(filePath); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	// Find the file
	var targetFile *torrent.File
	for _, f := range t.Files() {
		if f.Path() == filePath {
			targetFile = f
			break
		}
	}

	if targetFile == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("file not found"), "")
		return
	}

	// Set priority to off to prevent re-downloading
	targetFile.SetPriority(torrent.PiecePriorityNone)

	// Try to delete the file from disk
	fullPath := filepath.Join(s.config.DownloadDir, filePath)
	os.Remove(fullPath)

	w.WriteHeader(http.StatusNoContent)
}

// handleStartSeeding handles POST /api/torrents/{infoHash}/seed
func (s *Server) handleStartSeeding(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid path"), "")
		return
	}

	infoHash := pathParts[3]
	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	t.AllowDataUpload()
	s.seedStartTimes[infoHash] = time.Now()
	log.Printf("Started seeding: %s", t.Name())
	w.WriteHeader(http.StatusNoContent)
}

// handleStopSeeding handles DELETE /api/torrents/{infoHash}/seed
func (s *Server) handleStopSeeding(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid path"), "")
		return
	}

	infoHash := pathParts[3]
	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	t.DisallowDataUpload()
	delete(s.seedStartTimes, infoHash)
	log.Printf("Stopped seeding: %s", t.Name())
	w.WriteHeader(http.StatusNoContent)
}

// handleExportTorrent handles GET /api/torrents/{infoHash}/export
func (s *Server) handleExportTorrent(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid path"), "")
		return
	}

	infoHash := pathParts[3]
	if err := validateInfoHash(infoHash); err != nil {
		writeError(w, http.StatusBadRequest, err, "")
		return
	}

	hash := infohash.FromHexString(infoHash)
	t, ok := s.client.Torrent(hash)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("torrent not found"), "")
		return
	}

	// Get the metainfo
	metainfo := t.Metainfo()

	// Set headers for file download
	filename := fmt.Sprintf("%s.torrent", t.Name())
	w.Header().Set("Content-Type", "application/x-bittorrent")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	// Write the torrent file directly
	if err := metainfo.Write(w); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to write torrent file"), "")
		return
	}
}

// setupRoutes sets up HTTP routes
func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Auth routes (no middleware)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/check", s.handleCheckAuth)

	// API routes (with auth middleware)
	mux.HandleFunc("/api/health", s.authMiddleware(s.handleHealth))
	mux.HandleFunc("/api/torrents", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleGetTorrents(w, r)
		case http.MethodPost:
			s.handlePostTorrents(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"), "")
		}
	}))
	mux.HandleFunc("/api/torrents/", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/files") {
			if r.Method == http.MethodGet {
				s.handleGetTorrentFiles(w, r)
			} else {
				writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"), "")
			}
		} else if strings.HasSuffix(r.URL.Path, "/file") {
			switch r.Method {
			case http.MethodGet:
				s.handleGetFile(w, r)
			case http.MethodHead:
				s.handleHeadFile(w, r)
			case http.MethodDelete:
				s.handleDeleteFile(w, r)
			default:
				writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"), "")
			}
		} else if strings.HasSuffix(r.URL.Path, "/seed") {
			switch r.Method {
			case http.MethodPost:
				s.handleStartSeeding(w, r)
			case http.MethodDelete:
				s.handleStopSeeding(w, r)
			default:
				writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"), "")
			}
		} else if strings.HasSuffix(r.URL.Path, "/export") {
			if r.Method == http.MethodGet {
				s.handleExportTorrent(w, r)
			} else {
				writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"), "")
			}
		} else {
			switch r.Method {
			case http.MethodGet:
				s.handleGetTorrent(w, r)
			case http.MethodDelete:
				s.handleDeleteTorrent(w, r)
			default:
				writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"), "")
			}
		}
	}))

	// Static files
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Serve index.html for root path
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			indexFile, err := staticFiles.Open("static/index.html")
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer indexFile.Close()

			w.Header().Set("Content-Type", "text/html")
			io.Copy(w, indexFile)
		} else {
			http.NotFound(w, r)
		}
	})

	return mux
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	username := getEnv("TORRENTUI_USERNAME", "")
	password := getEnv("TORRENTUI_PASSWORD", "")
	secureCookie := getEnv("TORRENTUI_SECURE_COOKIE", "false") == "true"

	var passwordHash string
	if password != "" {
		var err error
		passwordHash, err = hashPassword(password)
		if err != nil {
			log.Fatalf("Failed to hash password: %v", err)
		}
	}

	config := &Config{
		ListenAddr:          getEnv("LISTEN_ADDR", ":8080"),
		DownloadDir:         getEnv("DOWNLOAD_DIR", "./downloads"),
		SessionDir:          getEnv("SESSION_DIR", "./session"),
		MaxUploadRateKBPS:   getEnvInt64("MAX_UPLOAD_RATE_KBPS", 0),
		MaxDownloadRateKBPS: getEnvInt64("MAX_DOWNLOAD_RATE_KBPS", 0),
		Username:            username,
		PasswordHash:        passwordHash,
		SessionTimeout:      time.Duration(getEnvInt64("SESSION_TIMEOUT_HOURS", 24)) * time.Hour,
		SecureCookie:        secureCookie,
		TorrentListenPort:   int(getEnvInt64("TORRENT_LISTEN_PORT", 0)),
		PublicIP:            getEnv("PUBLIC_IP", ""),
	}

	// Security warnings
	if username != "" && !secureCookie {
		log.Println("⚠️  WARNING: Secure cookie disabled. Session tokens will be sent over unencrypted connections.")
		log.Println("⚠️  Set TORRENTUI_SECURE_COOKIE=true and use HTTPS in production!")
	}

	return config
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt64 gets an environment variable as int64 with a default value
func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func main() {
	// Setup logging
	logFile := os.Getenv("TORRENTUI_LOG_FILE")
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer file.Close()
		log.SetOutput(file)
	}

	// Load configuration
	config := loadConfig()

	// Create server
	server, err := NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	// Start session cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			server.cleanupExpiredSessions()
		}
	}()

	// Setup routes and start server
	mux := server.setupRoutes()

	if config.Username != "" {
		log.Printf("TorrentUI starting on %s (authentication enabled)", config.ListenAddr)
	} else {
		log.Printf("TorrentUI starting on %s (no authentication)", config.ListenAddr)
	}

	if err := http.ListenAndServe(config.ListenAddr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
