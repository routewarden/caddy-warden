package caddywarden

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RouteWarden{})
	httpcaddyfile.RegisterHandlerDirective("routewarden", parseCaddyfile)
}

// RouteWarden is a Caddy v2 HTTP middleware module that blocks reconnaissance
// scans, sensitive file exposure, and path-evasion attacks.
type RouteWarden struct {
	Enabled                    bool            `json:"enabled,omitempty"`
	EnableDefaultPatterns      bool            `json:"enable_default_patterns,omitempty"`
	EnableDefaultAllowPatterns bool            `json:"enable_default_allow_patterns,omitempty"`
	PathPatterns               []string        `json:"path_patterns,omitempty"`
	BlockPatterns              []string        `json:"block_patterns,omitempty"`
	AllowPatterns              []string        `json:"allow_patterns,omitempty"`
	AllowedIPs                 []string        `json:"allowed_ips,omitempty"`
	Methods                    []string        `json:"methods,omitempty"`
	CheckQuery                 bool            `json:"check_query,omitempty"`
	StatusCode                 int             `json:"status_code,omitempty"`
	CustomResponseText         string          `json:"custom_response_text,omitempty"`
	SilentDrop                 bool            `json:"silent_drop,omitempty"`
	Debug                      bool            `json:"debug,omitempty"`
	Response                   *ResponseConfig `json:"response,omitempty"`

	logger          *zap.Logger
	methods         map[string]struct{}
	compiledBlock   []*regexp.Regexp
	compiledAllow   []*regexp.Regexp
	ipFilter        *IPFilter
	responseHandler *ResponseHandler
}

// CaddyModule returns the Caddy module information.
func (RouteWarden) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.routewarden",
		New: func() caddy.Module {
			return &RouteWarden{
				Enabled:                    true,
				EnableDefaultPatterns:      true,
				EnableDefaultAllowPatterns: true,
				Methods:                    []string{"GET"},
				Response:                   DefaultResponseConfig(),
			}
		},
	}
}

// Provision sets up the module and pre-compiles regexes and IP filters.
func (rw *RouteWarden) Provision(ctx caddy.Context) error {
	rw.logger = ctx.Logger(rw)

	if rw.Response == nil {
		rw.Response = DefaultResponseConfig()
	}

	// Initialize Methods Filter (defaults to ["GET"])
	methodsMap := make(map[string]struct{})
	if len(rw.Methods) == 0 {
		methodsMap["GET"] = struct{}{}
	} else {
		for _, m := range rw.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				methodsMap[m] = struct{}{}
			}
		}
		if len(methodsMap) == 0 {
			methodsMap["GET"] = struct{}{}
		}
	}
	rw.methods = methodsMap

	// 1. Compile Block Patterns
	var allBlockPatterns []string
	if rw.EnableDefaultPatterns {
		allBlockPatterns = append(allBlockPatterns, DefaultBlockPatterns...)
	}
	allBlockPatterns = append(allBlockPatterns, rw.PathPatterns...)
	allBlockPatterns = append(allBlockPatterns, rw.BlockPatterns...)

	rw.compiledBlock = make([]*regexp.Regexp, 0, len(allBlockPatterns))
	for _, p := range allBlockPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("routewarden: invalid block regex %q: %w", p, err)
		}
		rw.compiledBlock = append(rw.compiledBlock, re)
	}

	// 2. Compile Allow Patterns
	var allAllowPatterns []string
	if rw.EnableDefaultAllowPatterns {
		allAllowPatterns = append(allAllowPatterns, DefaultAllowPatterns...)
	}
	allAllowPatterns = append(allAllowPatterns, rw.AllowPatterns...)

	rw.compiledAllow = make([]*regexp.Regexp, 0, len(allAllowPatterns))
	for _, p := range allAllowPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("routewarden: invalid allow regex %q: %w", p, err)
		}
		rw.compiledAllow = append(rw.compiledAllow, re)
	}

	// 3. Initialize IP Filter
	if len(rw.AllowedIPs) > 0 {
		filter, err := NewIPFilter(rw.AllowedIPs)
		if err != nil {
			return fmt.Errorf("routewarden: invalid allowed_ips config: %w", err)
		}
		rw.ipFilter = filter
	}

	// 4. Initialize Response Handler
	respHandler, err := NewResponseHandler(rw.Response, rw.StatusCode, rw.CustomResponseText, rw.SilentDrop)
	if err != nil {
		return fmt.Errorf("routewarden: invalid response config: %w", err)
	}
	respHandler.SetLogger(rw.logger, rw.Debug)
	rw.responseHandler = respHandler

	if rw.Debug && rw.logger != nil {
		rw.logger.Debug("routewarden: provisioned successfully",
			zap.Int("compiled_block_patterns", len(rw.compiledBlock)),
			zap.Int("compiled_allow_patterns", len(rw.compiledAllow)),
			zap.Int("allowed_ips", len(rw.AllowedIPs)),
			zap.Strings("methods", rw.Methods),
			zap.Bool("check_query", rw.CheckQuery),
			zap.String("response_mode", rw.Response.Mode),
		)
	}

	return nil
}

// Validate ensures the configuration is valid.
func (rw *RouteWarden) Validate() error {
	if rw.Response != nil && rw.Response.StatusCode != 0 {
		if rw.Response.StatusCode < 100 || rw.Response.StatusCode > 599 {
			return fmt.Errorf("routewarden: statusCode must be between 100 and 599, got %d", rw.Response.StatusCode)
		}
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (rw *RouteWarden) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	if !rw.Enabled {
		return next.ServeHTTP(w, req)
	}

	// Only inspect requests whose HTTP method matches configured verbs (default: GET)
	if _, matchesMethod := rw.methods[strings.ToUpper(req.Method)]; !matchesMethod {
		if rw.Debug && rw.logger != nil {
			rw.logger.Debug("routewarden: method not inspected",
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path),
			)
		}
		return next.ServeHTTP(w, req)
	}

	// Stage 1: IP Whitelist bypass
	if rw.ipFilter != nil {
		clientIP := ExtractClientIP(req)
		allowed := rw.ipFilter.IsAllowed(req)
		if rw.Debug && rw.logger != nil {
			rw.logger.Debug("routewarden: evaluated client ip",
				zap.String("extracted_ip", clientIP),
				zap.String("remote_addr", req.RemoteAddr),
				zap.Bool("whitelisted", allowed),
			)
		}
		if allowed {
			return next.ServeHTTP(w, req)
		}
	}

	// Stage 2: Anti-Evasion Normalization
	candidatePaths := ExtractCandidatePaths(req.URL.RawPath, req.URL.Path, req.RequestURI)
	if rw.Debug && rw.logger != nil {
		rw.logger.Debug("routewarden: evaluating candidate paths",
			zap.Strings("candidate_paths", candidatePaths),
			zap.String("client_ip", req.RemoteAddr),
		)
	}

	// Stage 3: Allow Patterns (Explicit overrides)
	for _, p := range candidatePaths {
		for _, re := range rw.compiledAllow {
			if re.MatchString(p) {
				if rw.Debug && rw.logger != nil {
					rw.logger.Debug("routewarden: path allowed by pattern",
						zap.String("path", p),
						zap.String("pattern", re.String()),
					)
				}
				return next.ServeHTTP(w, req)
			}
		}
	}

	// Stage 4: Block Patterns Match
	var blockedByPattern string
	isBlocked := false

	for _, p := range candidatePaths {
		for _, re := range rw.compiledBlock {
			if re.MatchString(p) {
				isBlocked = true
				blockedByPattern = re.String()
				if rw.Debug && rw.logger != nil {
					rw.logger.Debug("routewarden: path matched block pattern",
						zap.String("candidate_path", p),
						zap.String("matched_pattern", blockedByPattern),
					)
				}
				break
			}
		}
		if isBlocked {
			break
		}
	}

	// Optional Query String Inspection
	if !isBlocked && rw.CheckQuery && req.URL.RawQuery != "" {
		unescapedQuery, err := url.QueryUnescape(req.URL.RawQuery)
		if err != nil {
			unescapedQuery = req.URL.RawQuery
		}

		queryCandidates := []string{req.URL.RawQuery, unescapedQuery}
		if parsedQuery, err := url.ParseQuery(req.URL.RawQuery); err == nil {
			for _, vals := range parsedQuery {
				for _, v := range vals {
					queryCandidates = append(queryCandidates, v)
					queryCandidates = append(queryCandidates, ExtractCandidatePaths(v, v, v)...)
				}
			}
		}
		if rw.Debug && rw.logger != nil {
			rw.logger.Debug("routewarden: checking query candidates",
				zap.Strings("query_candidates", queryCandidates),
			)
		}
		for _, q := range queryCandidates {
			for _, re := range rw.compiledBlock {
				if re.MatchString(q) {
					isBlocked = true
					blockedByPattern = re.String()
					if rw.Debug && rw.logger != nil {
						rw.logger.Debug("routewarden: query candidate matched block pattern",
							zap.String("query_candidate", q),
							zap.String("matched_pattern", blockedByPattern),
						)
					}
					break
				}
			}
			if isBlocked {
				break
			}
		}
	}

	if isBlocked {
		if rw.logger != nil {
			rw.logger.Warn("routewarden: blocked sensitive request",
				zap.String("client_ip", req.RemoteAddr),
				zap.String("path", req.URL.Path),
				zap.String("pattern", blockedByPattern),
				zap.String("mode", rw.Response.Mode),
			)
		}
		rw.responseHandler.ServeBlockedRequest(w, req)
		return nil
	}

	if rw.Debug && rw.logger != nil {
		rw.logger.Debug("routewarden: request passed inspection",
			zap.String("path", req.URL.Path),
			zap.String("method", req.Method),
		)
	}

	return next.ServeHTTP(w, req)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*RouteWarden)(nil)
	_ caddy.Validator             = (*RouteWarden)(nil)
	_ caddyhttp.MiddlewareHandler = (*RouteWarden)(nil)
	_ caddyfile.Unmarshaler       = (*RouteWarden)(nil)
)
