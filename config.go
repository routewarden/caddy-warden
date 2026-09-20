package caddywarden

// DefaultBlockPatterns contains well-known sensitive endpoints and file extensions.
var DefaultBlockPatterns = []string{
	// Sensitive extensions & environment files (e.g. .env, .env.local, .txt, .log, .bak, .backup, .sql, .conf, .config, .ini, .yaml, .yml)
	`(?i)(^|/)(\.env.*|.*\.(txt|log|bak|backup|sql|conf|config|ini|yaml|yml))$`,
	// Version control & sensitive hidden directories
	`(?i)(^|/)\.(git|svn|hg|bzr|cvs)(/.*|$)`,
	// Cloud & infra credentials
	`(?i)(^|/)\.(aws|ssh|kube|docker)(/.*|$)`,
	// Database & server dump files / archives
	`(?i).*\.(tar|tar\.gz|tgz|zip|rar|7z|gz|bz2|iso|dump|sqlite|sqlite3|db)$`,
	// Common sensitive admin & debug endpoints
	`(?i)(^|/)(phpinfo\.php|info\.php|server-status|server-info|actuator(/.*)?|metrics|heapdump|trace|env)$`,
	// Package manager files & lockfiles
	`(?i)(^|/)(composer\.(json|lock)|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile|Pipfile\.lock|requirements\.txt)$`,
	// TLS & cryptographic private keys, certificates, keystores
	`(?i).*\.(pem|key|crt|pfx|p12|jks|kdb)$`,
	// Container & orchestration manifests and configs
	`(?i)(^|/)(dockerfile.*|docker-compose.*\.ya?ml)$`,
	// System & macOS metadata files
	`(?i)(^|/)\.ds_store$`,
	// Web framework and CMS sensitive configuration files
	`(?i)(^|/)(wp-config\.php.*|configuration\.php.*|settings\.py|local_settings\.py)$`,
}

// DefaultAllowPatterns contains typical legitimate endpoints that might otherwise match broad patterns.
var DefaultAllowPatterns = []string{
	`(?i)^/robots\.txt$`,
	`(?i)^/sitemap.*\.xml$`,
	`(?i)^/ads\.txt$`,
	`(?i)^/security\.txt$`,
	`(?i)^/\.well-known(/.*)?$`,
}

// CaptchaConfig holds captcha configuration options.
type CaptchaConfig struct {
	Provider string `json:"provider,omitempty"` // "turnstile", "hcaptcha", "recaptcha", or "custom"
	SiteKey  string `json:"siteKey,omitempty"`  // Public site key
	Title    string `json:"title,omitempty"`    // Challenge page title
	Template string `json:"template,omitempty"` // Custom HTML template
}

// ResponseConfig defines how blocked requests should be answered.
type ResponseConfig struct {
	Mode                     string            `json:"mode,omitempty"`                     // "text", "json", "html", "captcha", "redirect", "silentDrop", "gzipBomb", "tarpit", "fakeSuccess", "rateLimitChallenge", "proxy", "infiniteStream", "xml"
	StatusCode               int               `json:"statusCode,omitempty"`               // HTTP status code (e.g. 403, 404, 429)
	ContentType              string            `json:"contentType,omitempty"`              // Custom Content-Type header override
	Body                     string            `json:"body,omitempty"`                     // Response payload (JSON string, HTML, or text)
	Headers                  map[string]string `json:"headers,omitempty"`                  // Custom response headers
	RedirectURL              string            `json:"redirectUrl,omitempty"`              // Target URL when Mode is "redirect"
	ProxyURL                 string            `json:"proxyUrl,omitempty"`                 // Target honeypot backend when Mode is "proxy"
	Captcha                  *CaptchaConfig    `json:"captcha,omitempty"`                  // Captcha settings when Mode is "captcha"
	GzipBombMB               int               `json:"gzipBombMB,omitempty"`               // Uncompressed size in Megabytes for gzipBomb mode (default: 10)
	RetryAfterSeconds        int               `json:"retryAfterSeconds,omitempty"`        // Seconds for Retry-After header when Mode is "rateLimitChallenge" (default: 300)
	TarpitDelayMs            int               `json:"tarpitDelayMs,omitempty"`            // Milliseconds between bytes for tarpit mode (default: 1000)
	TarpitMaxDurationSeconds int               `json:"tarpitMaxDurationSeconds,omitempty"` // Max seconds before terminating tarpit connection (default: 60)
	StreamSizeMB             int               `json:"streamSizeMB,omitempty"`             // Size in Megabytes for infiniteStream/garbageStream mode (default: 100)
}

// DefaultResponseConfig creates default response settings.
func DefaultResponseConfig() *ResponseConfig {
	return &ResponseConfig{
		Mode:                     "json",
		StatusCode:               403,
		Body:                     "",
		GzipBombMB:               10,
		RetryAfterSeconds:        300,
		TarpitDelayMs:            1000,
		TarpitMaxDurationSeconds: 60,
		StreamSizeMB:             100,
	}
}
