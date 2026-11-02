package caddywarden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RouteWarden{})
	caddy.RegisterModule(RouteWardenSnakeCase{})
	httpcaddyfile.RegisterDirectiveOrder("routewarden", httpcaddyfile.Before, "reverse_proxy")
	httpcaddyfile.RegisterDirectiveOrder("route_warden", httpcaddyfile.Before, "reverse_proxy")
	httpcaddyfile.RegisterHandlerDirective("routewarden", parseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("route_warden", parseCaddyfile)
}

// RouteWardenSnakeCase is a Caddy module alias for the "route_warden" handler ID.
type RouteWardenSnakeCase struct {
	RouteWarden
}

// CaddyModule returns the Caddy module information for route_warden.
func (RouteWardenSnakeCase) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.route_warden",
		New: func() caddy.Module {
			return &RouteWardenSnakeCase{
				RouteWarden: RouteWarden{
					Enabled:                    true,
					EnableDefaultPatterns:      true,
					EnableDefaultAllowPatterns: true,
				},
			}
		},
	}
}

// RouteWarden is a Caddy v2 HTTP middleware module that blocks reconnaissance
// scans, sensitive file exposure, and path-evasion attacks.
type RouteWarden struct {
	// ConfigFile is an optional path to a routewarden.json file that provides base
	// configuration. Inline Caddyfile/JSON fields take precedence over any values
	// set in the file, allowing per-site overrides on top of a shared config.
	ConfigFile                 string          `json:"config_file,omitempty"`
	Enabled                    bool            `json:"enabled"`
	EnableDefaultPatterns      bool            `json:"enable_default_patterns"`
	EnableDefaultAllowPatterns bool            `json:"enable_default_allow_patterns"`
	BlockPatterns              []string        `json:"block_patterns,omitempty"`
	AllowPatterns              []string        `json:"allow_patterns,omitempty"`
	AllowedASNs                []string        `json:"allowed_asns,omitempty"`
	BlockedASNs                []string        `json:"blocked_asns,omitempty"`
	ASNDB                      string          `json:"asn_db,omitempty"`
	BotDefenseLevel            string          `json:"bot_defense_level,omitempty"`
	BotDefenseLevelCamel       string          `json:"botDefenseLevel,omitempty"`
	BlockAIBots                bool            `json:"block_ai_bots,omitempty"`
	AIBotProfile               string          `json:"ai_bot_profile,omitempty"`
	BlockUserAgents            []string        `json:"block_user_agents,omitempty"`
	AllowUserAgents            []string        `json:"allow_user_agents,omitempty"`
	HoneypotTrapPaths          []string        `json:"honeypot_trap_paths,omitempty"`
	EnableRobotsTxtHoneypot    bool            `json:"enable_robots_txt_honeypot,omitempty"`
	RobotsTxtHoneypotSecret    string          `json:"robots_txt_honeypot_secret,omitempty"`
	TrapBanDuration            string          `json:"trap_ban_duration,omitempty"`
	VerifySearchEngineBots     bool            `json:"verify_search_engine_bots,omitempty"`
	DetectBrowserImpersonation bool            `json:"detect_browser_impersonation,omitempty"`
	BlockScriptClients         bool            `json:"block_script_clients,omitempty"`
	BlockCloudHosts            bool            `json:"block_cloud_hosts,omitempty"`
	AllowedIPs                 []string        `json:"allowed_ips,omitempty"`
	TrustedProxies             []string        `json:"trusted_proxies,omitempty"`
	Methods                    []string        `json:"methods,omitempty"`
	CheckQuery                 bool            `json:"check_query,omitempty"`
	CheckHeaders               []string        `json:"check_headers,omitempty"`
	CheckBody                  bool            `json:"check_body,omitempty"`
	CheckBodyMaxBytes          int64           `json:"check_body_max_bytes,omitempty"`
	CheckBodyPatterns          []string        `json:"check_body_patterns,omitempty"`
	StatusCode                 int             `json:"status_code,omitempty"`
	CustomResponseText         string          `json:"custom_response_text,omitempty"`
	Mode                       string          `json:"mode,omitempty"`
	Debug                      bool            `json:"debug,omitempty"`
	SecurityLog                bool            `json:"security_log,omitempty"`
	Response                   *ResponseConfig `json:"response,omitempty"`
	ExplicitFields             []string        `json:"explicit_fields,omitempty"`

	logger          *zap.Logger
	methods         map[string]struct{}
	compiledBlock   []*regexp.Regexp
	compiledAllow   []*regexp.Regexp
	compiledBody    []*regexp.Regexp
	compiledBlockUA []*regexp.Regexp
	compiledAllowUA []*regexp.Regexp
	ipFilter          *IPFilter
	responseHandler   *ResponseHandler
	banTable          *BanTable
	parsedBanDuration time.Duration
	fcrdnsVerifier    *FCrDNSVerifier
}

func (rw *RouteWarden) markExplicit(field string) {
	if slices.Contains(rw.ExplicitFields, field) {
		return
	}
	rw.ExplicitFields = append(rw.ExplicitFields, field)
}

func (rw *RouteWarden) isExplicit(fields ...string) bool {
	for _, f := range fields {
		if slices.Contains(rw.ExplicitFields, f) {
			return true
		}
	}
	return false
}

// UnmarshalJSON implements custom JSON unmarshaling to track explicitly provided fields,
// and supports both snake_case and camelCase fields from Caddy JSON configurations.
func (rw *RouteWarden) UnmarshalJSON(data []byte) error {
	type alias RouteWarden
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*rw = RouteWarden(a)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		for k := range raw {
			rw.markExplicit(k)
		}
	}

	var camel struct {
		ConfigFile                 *string  `json:"configFile"`
		EnableDefaultPatterns      *bool    `json:"enableDefaultPatterns"`
		EnableDefaultAllowPatterns *bool    `json:"enableDefaultAllowPatterns"`
		BlockPatterns              []string `json:"blockPatterns"`
		AllowPatterns              []string `json:"allowPatterns"`
		AllowedASNs                []string `json:"allowedASNs"`
		BlockedASNs                []string `json:"blockedASNs"`
		ASNDB                      *string  `json:"asnDB"`
		BotDefenseLevel            *string  `json:"botDefenseLevel"`
		BlockAIBots                *bool    `json:"blockAIBots"`
		AIBotProfile               *string  `json:"aiBotProfile"`
		BlockUserAgents            []string `json:"blockUserAgents"`
		AllowUserAgents            []string `json:"allowUserAgents"`
		HoneypotTrapPaths          []string `json:"honeypotTrapPaths"`
		EnableRobotsTxtHoneypot    *bool    `json:"enableRobotsTxtHoneypot"`
		RobotsTxtHoneypotSecret    *string  `json:"robotsTxtHoneypotSecret"`
		TrapBanDuration            *string  `json:"trapBanDuration"`
		VerifySearchEngineBots     *bool    `json:"verifySearchEngineBots"`
		DetectBrowserImpersonation *bool    `json:"detectBrowserImpersonation"`
		BlockScriptClients              *bool    `json:"blockScriptClients"`
		BlockScriptClientsSnake         *bool    `json:"block_script_clients"`
		BlockCloudHosts                 *bool    `json:"blockCloudHosts"`
		BlockCloudHostsSnake            *bool    `json:"block_cloud_hosts"`
		AllowedIPs                      []string `json:"allowedIps"`
		TrustedProxies             []string `json:"trustedProxies"`
		CheckQuery                 *bool    `json:"checkQuery"`
		CheckHeaders               []string `json:"checkHeaders"`
		CheckBody                  *bool    `json:"checkBody"`
		CheckBodyMaxBytes          *int64   `json:"checkBodyMaxBytes"`
		CheckBodyPatterns          []string `json:"checkBodyPatterns"`
		StatusCode                 *int     `json:"statusCode"`
		CustomResponseText         *string  `json:"customResponseText"`
		SecurityLog                *bool    `json:"securityLog"`
	}
	if err := json.Unmarshal(data, &camel); err == nil {
		if camel.ConfigFile != nil {
			rw.ConfigFile = *camel.ConfigFile
		}
		if camel.EnableDefaultPatterns != nil {
			rw.EnableDefaultPatterns = *camel.EnableDefaultPatterns
		}
		if camel.EnableDefaultAllowPatterns != nil {
			rw.EnableDefaultAllowPatterns = *camel.EnableDefaultAllowPatterns
		}
		if camel.BlockPatterns != nil {
			rw.BlockPatterns = camel.BlockPatterns
		}
		if camel.AllowPatterns != nil {
			rw.AllowPatterns = camel.AllowPatterns
		}
		if camel.AllowedASNs != nil {
			rw.AllowedASNs = camel.AllowedASNs
		}
		if camel.BlockedASNs != nil {
			rw.BlockedASNs = camel.BlockedASNs
		}
		if camel.ASNDB != nil {
			rw.ASNDB = *camel.ASNDB
		}
		if camel.BotDefenseLevel != nil {
			rw.BotDefenseLevel = *camel.BotDefenseLevel
		}
		if camel.BlockAIBots != nil {
			rw.BlockAIBots = *camel.BlockAIBots
		}
		if camel.AIBotProfile != nil {
			rw.AIBotProfile = *camel.AIBotProfile
		}
		if camel.BlockUserAgents != nil {
			rw.BlockUserAgents = camel.BlockUserAgents
		}
		if camel.AllowUserAgents != nil {
			rw.AllowUserAgents = camel.AllowUserAgents
		}
		if camel.HoneypotTrapPaths != nil {
			rw.HoneypotTrapPaths = camel.HoneypotTrapPaths
		}
		if camel.EnableRobotsTxtHoneypot != nil {
			rw.EnableRobotsTxtHoneypot = *camel.EnableRobotsTxtHoneypot
		}
		if camel.RobotsTxtHoneypotSecret != nil {
			rw.RobotsTxtHoneypotSecret = *camel.RobotsTxtHoneypotSecret
		}
		if camel.TrapBanDuration != nil {
			rw.TrapBanDuration = *camel.TrapBanDuration
		}
		if camel.VerifySearchEngineBots != nil {
			rw.VerifySearchEngineBots = *camel.VerifySearchEngineBots
		}
		if camel.DetectBrowserImpersonation != nil {
			rw.DetectBrowserImpersonation = *camel.DetectBrowserImpersonation
		}
		if camel.BlockScriptClients != nil {
			rw.BlockScriptClients = *camel.BlockScriptClients
		} else if camel.BlockScriptClientsSnake != nil {
			rw.BlockScriptClients = *camel.BlockScriptClientsSnake
		}
		if camel.BlockCloudHosts != nil {
			rw.BlockCloudHosts = *camel.BlockCloudHosts
		} else if camel.BlockCloudHostsSnake != nil {
			rw.BlockCloudHosts = *camel.BlockCloudHostsSnake
		}
		if camel.AllowedIPs != nil {
			rw.AllowedIPs = camel.AllowedIPs
		}
		if camel.TrustedProxies != nil {
			rw.TrustedProxies = camel.TrustedProxies
		}
		if camel.CheckQuery != nil {
			rw.CheckQuery = *camel.CheckQuery
		}
		if camel.CheckHeaders != nil {
			rw.CheckHeaders = camel.CheckHeaders
		}
		if camel.CheckBody != nil {
			rw.CheckBody = *camel.CheckBody
		}
		if camel.CheckBodyMaxBytes != nil {
			rw.CheckBodyMaxBytes = *camel.CheckBodyMaxBytes
		}
		if camel.CheckBodyPatterns != nil {
			rw.CheckBodyPatterns = camel.CheckBodyPatterns
		}
		if camel.StatusCode != nil {
			rw.StatusCode = *camel.StatusCode
		}
		if camel.CustomResponseText != nil {
			rw.CustomResponseText = *camel.CustomResponseText
		}
		if camel.SecurityLog != nil {
			rw.SecurityLog = *camel.SecurityLog
		}
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (RouteWarden) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.routewarden",
		New: func() caddy.Module {
			return &RouteWarden{
				Enabled:                    true,
				EnableDefaultPatterns:      true,
				EnableDefaultAllowPatterns: true,
			}
		},
	}
}

// Provision sets up the module and pre-compiles regexes and IP filters.
func (rw *RouteWarden) Provision(ctx caddy.Context) error {
	rw.logger = ctx.Logger(rw)

	// If config_file is set, load it as the base and re-apply any inline values on top.
	// This lets operators keep a shared routewarden.json and override individual
	// fields (e.g. mode, allowed_ips) per site inside the Caddyfile.
	if rw.ConfigFile != "" {
		fileData, err := os.ReadFile(rw.ConfigFile)
		if err != nil {
			return fmt.Errorf("routewarden: cannot read config_file %q: %w", rw.ConfigFile, err)
		}

		type sharedResponseConfig struct {
			Mode                          *string           `json:"mode"`
			StatusCode                    *int              `json:"statusCode"`
			StatusCodeSnake               *int              `json:"status_code"`
			ContentType                   *string           `json:"contentType"`
			ContentTypeSnake              *string           `json:"content_type"`
			Body                          *string           `json:"body"`
			Headers                       map[string]string `json:"headers"`
			RedirectURL                   *string           `json:"redirectUrl"`
			RedirectURLSnake              *string           `json:"redirect_url"`
			ProxyURL                      *string           `json:"proxyUrl"`
			ProxyURLSnake                 *string           `json:"proxy_url"`
			Captcha                       *CaptchaConfig    `json:"captcha"`
			GzipBombMB                    *float64          `json:"gzipBombMB"`
			GzipBombMBSnake               *float64          `json:"gzip_bomb_mb"`
			RetryAfterSeconds             *int              `json:"retryAfterSeconds"`
			RetryAfterSecondsSnake        *int              `json:"retry_after_seconds"`
			TarpitDelayMs                 *int              `json:"tarpitDelayMs"`
			TarpitDelayMsSnake            *int              `json:"tarpit_delay_ms"`
			TarpitMaxDurationSeconds      *int              `json:"tarpitMaxDurationSeconds"`
			TarpitMaxDurationSecondsSnake *int              `json:"tarpit_max_duration_seconds"`
			StreamSizeMB                  *int              `json:"streamSizeMB"`
			StreamSizeMBSnake             *int              `json:"stream_size_mb"`
		}

		type sharedConfigFile struct {
			Enabled                         *bool                 `json:"enabled"`
			EnableDefaultPatterns           *bool                 `json:"enableDefaultPatterns"`
			EnableDefaultPatternsSnake      *bool                 `json:"enable_default_patterns"`
			EnableDefaultAllowPatterns      *bool                 `json:"enableDefaultAllowPatterns"`
			EnableDefaultAllowPatternsSnake *bool                 `json:"enable_default_allow_patterns"`
			BlockPatterns                   []string              `json:"blockPatterns"`
			BlockPatternsSnake              []string              `json:"block_patterns"`
			AllowPatterns                   []string              `json:"allowPatterns"`
			AllowPatternsSnake              []string              `json:"allow_patterns"`
			AllowedASNs                     []string              `json:"allowedASNs"`
			AllowedASNsSnake                []string              `json:"allowed_asns"`
			BlockedASNs                     []string              `json:"blockedASNs"`
			BlockedASNsSnake                []string              `json:"blocked_asns"`
			ASNDB                           string                `json:"asnDB"`
			ASNDBSnake                      string                `json:"asn_db"`
			BotDefenseLevel                 *string               `json:"botDefenseLevel"`
			BotDefenseLevelSnake            *string               `json:"bot_defense_level"`
			BlockAIBots                     *bool                 `json:"blockAIBots"`
			BlockAIBotsSnake                *bool                 `json:"block_ai_bots"`
			AIBotProfile                    *string               `json:"aiBotProfile"`
			AIBotProfileSnake               *string               `json:"ai_bot_profile"`
			BlockUserAgents                 []string              `json:"blockUserAgents"`
			BlockUserAgentsSnake            []string              `json:"block_user_agents"`
			AllowUserAgents                 []string              `json:"allowUserAgents"`
			AllowUserAgentsSnake            []string              `json:"allow_user_agents"`
			HoneypotTrapPaths               []string              `json:"honeypotTrapPaths"`
			HoneypotTrapPathsSnake          []string              `json:"honeypot_trap_paths"`
			EnableRobotsTxtHoneypot         *bool                 `json:"enableRobotsTxtHoneypot"`
			EnableRobotsTxtHoneypotSnake    *bool                 `json:"enable_robots_txt_honeypot"`
			RobotsTxtHoneypotSecret         *string               `json:"robotsTxtHoneypotSecret"`
			RobotsTxtHoneypotSecretSnake    *string               `json:"robots_txt_honeypot_secret"`
			TrapBanDuration                 *string               `json:"trapBanDuration"`
			TrapBanDurationSnake            *string               `json:"trap_ban_duration"`
			VerifySearchEngineBots          *bool                 `json:"verifySearchEngineBots"`
			VerifySearchEngineBotsSnake     *bool                 `json:"verify_search_engine_bots"`
			DetectBrowserImpersonation      *bool                 `json:"detectBrowserImpersonation"`
			DetectBrowserImpersonationSnake *bool                 `json:"detect_browser_impersonation"`
			BlockScriptClients              *bool                 `json:"blockScriptClients"`
			BlockScriptClientsSnake         *bool                 `json:"block_script_clients"`
			BlockCloudHosts                 *bool                 `json:"blockCloudHosts"`
			BlockCloudHostsSnake            *bool                 `json:"block_cloud_hosts"`
			AllowedIPs                      []string              `json:"allowedIps"`
			AllowedIPsSnake                 []string              `json:"allowed_ips"`
			TrustedProxies                  []string              `json:"trustedProxies"`
			TrustedProxiesSnake             []string              `json:"trusted_proxies"`
			Methods                         []string              `json:"methods"`
			CheckQuery                      *bool                 `json:"checkQuery"`
			CheckQuerySnake                 *bool                 `json:"check_query"`
			CheckHeaders                    []string              `json:"checkHeaders"`
			CheckHeadersSnake               []string              `json:"check_headers"`
			CheckBody                       *bool                 `json:"checkBody"`
			CheckBodySnake                  *bool                 `json:"check_body"`
			CheckBodyMaxBytes               *int64                `json:"checkBodyMaxBytes"`
			CheckBodyMaxBytesSnake          *int64                `json:"check_body_max_bytes"`
			CheckBodyPatterns               []string              `json:"checkBodyPatterns"`
			CheckBodyPatternsSnake          []string              `json:"check_body_patterns"`
			StatusCode                      *int                  `json:"statusCode"`
			StatusCodeSnake                 *int                  `json:"status_code"`
			CustomResponseText              *string               `json:"customResponseText"`
			CustomResponseTextSnake         *string               `json:"custom_response_text"`
			Mode                            *string               `json:"mode"`
			Debug                           *bool                 `json:"debug"`
			SecurityLog                     *bool                 `json:"securityLog"`
			SecurityLogSnake                *bool                 `json:"security_log"`
			Response                        *sharedResponseConfig `json:"response"`
		}

		var scf sharedConfigFile
		if err := json.Unmarshal(fileData, &scf); err != nil {
			return fmt.Errorf("routewarden: cannot parse config_file %q: %w", rw.ConfigFile, err)
		}

		fileCfg := RouteWarden{
			Enabled:                    true,
			EnableDefaultPatterns:      true,
			EnableDefaultAllowPatterns: true,
			Methods:                    []string{"GET"},
			Response:                   DefaultResponseConfig(),
		}

		if scf.Enabled != nil {
			fileCfg.Enabled = *scf.Enabled
		}
		if scf.EnableDefaultPatterns != nil {
			fileCfg.EnableDefaultPatterns = *scf.EnableDefaultPatterns
		} else if scf.EnableDefaultPatternsSnake != nil {
			fileCfg.EnableDefaultPatterns = *scf.EnableDefaultPatternsSnake
		}
		if scf.EnableDefaultAllowPatterns != nil {
			fileCfg.EnableDefaultAllowPatterns = *scf.EnableDefaultAllowPatterns
		} else if scf.EnableDefaultAllowPatternsSnake != nil {
			fileCfg.EnableDefaultAllowPatterns = *scf.EnableDefaultAllowPatternsSnake
		}
		if len(scf.BlockPatterns) > 0 {
			fileCfg.BlockPatterns = scf.BlockPatterns
		} else if len(scf.BlockPatternsSnake) > 0 {
			fileCfg.BlockPatterns = scf.BlockPatternsSnake
		}
		if len(scf.AllowPatterns) > 0 {
			fileCfg.AllowPatterns = scf.AllowPatterns
		} else if len(scf.AllowPatternsSnake) > 0 {
			fileCfg.AllowPatterns = scf.AllowPatternsSnake
		}
		if len(scf.AllowedASNs) > 0 {
			fileCfg.AllowedASNs = scf.AllowedASNs
		} else if len(scf.AllowedASNsSnake) > 0 {
			fileCfg.AllowedASNs = scf.AllowedASNsSnake
		}
		if len(scf.BlockedASNs) > 0 {
			fileCfg.BlockedASNs = scf.BlockedASNs
		} else if len(scf.BlockedASNsSnake) > 0 {
			fileCfg.BlockedASNs = scf.BlockedASNsSnake
		}
		fileCfg.ASNDB = scf.ASNDB
		if scf.ASNDBSnake != "" {
			fileCfg.ASNDB = scf.ASNDBSnake
		}
		if scf.BotDefenseLevel != nil {
			fileCfg.BotDefenseLevel = *scf.BotDefenseLevel
		} else if scf.BotDefenseLevelSnake != nil {
			fileCfg.BotDefenseLevel = *scf.BotDefenseLevelSnake
		}
		if fileCfg.BotDefenseLevel != "" {
			applyBotDefenseLevel(fileCfg.BotDefenseLevel, &fileCfg.BlockAIBots, &fileCfg.AIBotProfile, &fileCfg.DetectBrowserImpersonation, &fileCfg.BlockScriptClients, &fileCfg.VerifySearchEngineBots)
		}
		if scf.BlockAIBots != nil {
			fileCfg.BlockAIBots = *scf.BlockAIBots
		} else if scf.BlockAIBotsSnake != nil {
			fileCfg.BlockAIBots = *scf.BlockAIBotsSnake
		}
		if scf.AIBotProfile != nil {
			fileCfg.AIBotProfile = *scf.AIBotProfile
		} else if scf.AIBotProfileSnake != nil {
			fileCfg.AIBotProfile = *scf.AIBotProfileSnake
		}
		if len(scf.BlockUserAgents) > 0 {
			fileCfg.BlockUserAgents = scf.BlockUserAgents
		} else if len(scf.BlockUserAgentsSnake) > 0 {
			fileCfg.BlockUserAgents = scf.BlockUserAgentsSnake
		}
		if len(scf.AllowUserAgents) > 0 {
			fileCfg.AllowUserAgents = scf.AllowUserAgents
		} else if len(scf.AllowUserAgentsSnake) > 0 {
			fileCfg.AllowUserAgents = scf.AllowUserAgentsSnake
		}
		if len(scf.HoneypotTrapPaths) > 0 {
			fileCfg.HoneypotTrapPaths = scf.HoneypotTrapPaths
		} else if len(scf.HoneypotTrapPathsSnake) > 0 {
			fileCfg.HoneypotTrapPaths = scf.HoneypotTrapPathsSnake
		}
		if scf.EnableRobotsTxtHoneypot != nil {
			fileCfg.EnableRobotsTxtHoneypot = *scf.EnableRobotsTxtHoneypot
		} else if scf.EnableRobotsTxtHoneypotSnake != nil {
			fileCfg.EnableRobotsTxtHoneypot = *scf.EnableRobotsTxtHoneypotSnake
		}
		if scf.RobotsTxtHoneypotSecret != nil {
			fileCfg.RobotsTxtHoneypotSecret = *scf.RobotsTxtHoneypotSecret
		} else if scf.RobotsTxtHoneypotSecretSnake != nil {
			fileCfg.RobotsTxtHoneypotSecret = *scf.RobotsTxtHoneypotSecretSnake
		}
		if scf.TrapBanDuration != nil {
			fileCfg.TrapBanDuration = *scf.TrapBanDuration
		} else if scf.TrapBanDurationSnake != nil {
			fileCfg.TrapBanDuration = *scf.TrapBanDurationSnake
		}
		if scf.VerifySearchEngineBots != nil {
			fileCfg.VerifySearchEngineBots = *scf.VerifySearchEngineBots
		} else if scf.VerifySearchEngineBotsSnake != nil {
			fileCfg.VerifySearchEngineBots = *scf.VerifySearchEngineBotsSnake
		}
		if scf.DetectBrowserImpersonation != nil {
			fileCfg.DetectBrowserImpersonation = *scf.DetectBrowserImpersonation
		} else if scf.DetectBrowserImpersonationSnake != nil {
			fileCfg.DetectBrowserImpersonation = *scf.DetectBrowserImpersonationSnake
		}
		if scf.BlockScriptClients != nil {
			fileCfg.BlockScriptClients = *scf.BlockScriptClients
		} else if scf.BlockScriptClientsSnake != nil {
			fileCfg.BlockScriptClients = *scf.BlockScriptClientsSnake
		}
		if scf.BlockCloudHosts != nil {
			fileCfg.BlockCloudHosts = *scf.BlockCloudHosts
		} else if scf.BlockCloudHostsSnake != nil {
			fileCfg.BlockCloudHosts = *scf.BlockCloudHostsSnake
		}
		if len(scf.AllowedIPs) > 0 {
			fileCfg.AllowedIPs = scf.AllowedIPs
		} else if len(scf.AllowedIPsSnake) > 0 {
			fileCfg.AllowedIPs = scf.AllowedIPsSnake
		}
		if len(scf.TrustedProxies) > 0 {
			fileCfg.TrustedProxies = scf.TrustedProxies
		} else if len(scf.TrustedProxiesSnake) > 0 {
			fileCfg.TrustedProxies = scf.TrustedProxiesSnake
		}
		if len(scf.Methods) > 0 {
			fileCfg.Methods = scf.Methods
		}
		if scf.CheckQuery != nil {
			fileCfg.CheckQuery = *scf.CheckQuery
		} else if scf.CheckQuerySnake != nil {
			fileCfg.CheckQuery = *scf.CheckQuerySnake
		}
		if len(scf.CheckHeaders) > 0 {
			fileCfg.CheckHeaders = scf.CheckHeaders
		} else if len(scf.CheckHeadersSnake) > 0 {
			fileCfg.CheckHeaders = scf.CheckHeadersSnake
		}
		if scf.CheckBody != nil {
			fileCfg.CheckBody = *scf.CheckBody
		} else if scf.CheckBodySnake != nil {
			fileCfg.CheckBody = *scf.CheckBodySnake
		}
		if scf.CheckBodyMaxBytes != nil {
			fileCfg.CheckBodyMaxBytes = *scf.CheckBodyMaxBytes
		} else if scf.CheckBodyMaxBytesSnake != nil {
			fileCfg.CheckBodyMaxBytes = *scf.CheckBodyMaxBytesSnake
		}
		if len(scf.CheckBodyPatterns) > 0 {
			fileCfg.CheckBodyPatterns = scf.CheckBodyPatterns
		} else if len(scf.CheckBodyPatternsSnake) > 0 {
			fileCfg.CheckBodyPatterns = scf.CheckBodyPatternsSnake
		}
		if scf.StatusCode != nil {
			fileCfg.StatusCode = *scf.StatusCode
		} else if scf.StatusCodeSnake != nil {
			fileCfg.StatusCode = *scf.StatusCodeSnake
		}
		if scf.CustomResponseText != nil {
			fileCfg.CustomResponseText = *scf.CustomResponseText
		} else if scf.CustomResponseTextSnake != nil {
			fileCfg.CustomResponseText = *scf.CustomResponseTextSnake
		}
		if scf.Mode != nil {
			fileCfg.Mode = *scf.Mode
		}
		if scf.Debug != nil {
			fileCfg.Debug = *scf.Debug
		}
		if scf.SecurityLog != nil {
			fileCfg.SecurityLog = *scf.SecurityLog
		} else if scf.SecurityLogSnake != nil {
			fileCfg.SecurityLog = *scf.SecurityLogSnake
		}
		if scf.Response != nil {
			if fileCfg.Response == nil {
				fileCfg.Response = DefaultResponseConfig()
			}
			if scf.Response.Mode != nil {
				fileCfg.Response.Mode = *scf.Response.Mode
			}
			if scf.Response.StatusCode != nil {
				fileCfg.Response.StatusCode = *scf.Response.StatusCode
			} else if scf.Response.StatusCodeSnake != nil {
				fileCfg.Response.StatusCode = *scf.Response.StatusCodeSnake
			}
			if scf.Response.ContentType != nil {
				fileCfg.Response.ContentType = *scf.Response.ContentType
			} else if scf.Response.ContentTypeSnake != nil {
				fileCfg.Response.ContentType = *scf.Response.ContentTypeSnake
			}
			if scf.Response.Body != nil {
				fileCfg.Response.Body = *scf.Response.Body
			}
			if scf.Response.Headers != nil {
				fileCfg.Response.Headers = scf.Response.Headers
			}
			if scf.Response.RedirectURL != nil {
				fileCfg.Response.RedirectURL = *scf.Response.RedirectURL
			} else if scf.Response.RedirectURLSnake != nil {
				fileCfg.Response.RedirectURL = *scf.Response.RedirectURLSnake
			}
			if scf.Response.ProxyURL != nil {
				fileCfg.Response.ProxyURL = *scf.Response.ProxyURL
			} else if scf.Response.ProxyURLSnake != nil {
				fileCfg.Response.ProxyURL = *scf.Response.ProxyURLSnake
			}
			if scf.Response.Captcha != nil {
				fileCfg.Response.Captcha = scf.Response.Captcha
			}
			if scf.Response.GzipBombMB != nil {
				fileCfg.Response.GzipBombMB = *scf.Response.GzipBombMB
			} else if scf.Response.GzipBombMBSnake != nil {
				fileCfg.Response.GzipBombMB = *scf.Response.GzipBombMBSnake
			}
			if scf.Response.RetryAfterSeconds != nil {
				fileCfg.Response.RetryAfterSeconds = *scf.Response.RetryAfterSeconds
			} else if scf.Response.RetryAfterSecondsSnake != nil {
				fileCfg.Response.RetryAfterSeconds = *scf.Response.RetryAfterSecondsSnake
			}
			if scf.Response.TarpitDelayMs != nil {
				fileCfg.Response.TarpitDelayMs = *scf.Response.TarpitDelayMs
			} else if scf.Response.TarpitDelayMsSnake != nil {
				fileCfg.Response.TarpitDelayMs = *scf.Response.TarpitDelayMsSnake
			}
			if scf.Response.TarpitMaxDurationSeconds != nil {
				fileCfg.Response.TarpitMaxDurationSeconds = *scf.Response.TarpitMaxDurationSeconds
			} else if scf.Response.TarpitMaxDurationSecondsSnake != nil {
				fileCfg.Response.TarpitMaxDurationSeconds = *scf.Response.TarpitMaxDurationSecondsSnake
			}
			if scf.Response.StreamSizeMB != nil {
				fileCfg.Response.StreamSizeMB = *scf.Response.StreamSizeMB
			} else if scf.Response.StreamSizeMBSnake != nil {
				fileCfg.Response.StreamSizeMB = *scf.Response.StreamSizeMBSnake
			}
		}

		// Apply inline overrides: any explicitly configured inline property wins
		hasExplicit := len(rw.ExplicitFields) > 0

		if rw.isExplicit("enabled") {
			fileCfg.Enabled = rw.Enabled
		}
		if rw.isExplicit("enable_default_patterns") {
			fileCfg.EnableDefaultPatterns = rw.EnableDefaultPatterns
		}
		if rw.isExplicit("enable_default_allow_patterns") {
			fileCfg.EnableDefaultAllowPatterns = rw.EnableDefaultAllowPatterns
		}
		if len(rw.BlockPatterns) > 0 {
			fileCfg.BlockPatterns = rw.BlockPatterns
		}
		if len(rw.AllowPatterns) > 0 {
			fileCfg.AllowPatterns = rw.AllowPatterns
		}
		if rw.AllowedASNs != nil {
			fileCfg.AllowedASNs = rw.AllowedASNs
		}
		if rw.BlockedASNs != nil {
			fileCfg.BlockedASNs = rw.BlockedASNs
		}
		if rw.ASNDB != "" {
			fileCfg.ASNDB = rw.ASNDB
		}
		if rw.isExplicit("bot_defense_level", "botDefenseLevel") || rw.BotDefenseLevel != "" || rw.BotDefenseLevelCamel != "" {
			lvl := rw.BotDefenseLevel
			if lvl == "" {
				lvl = rw.BotDefenseLevelCamel
			}
			fileCfg.BotDefenseLevel = lvl
			fileCfg.applyBotDefense(lvl)
		}
		if rw.isExplicit("block_ai_bots", "blockAIBots") {
			fileCfg.BlockAIBots = rw.BlockAIBots
		}
		if rw.isExplicit("ai_bot_profile", "aiBotProfile") || rw.AIBotProfile != "" {
			fileCfg.AIBotProfile = rw.AIBotProfile
		}
		if len(rw.BlockUserAgents) > 0 {
			fileCfg.BlockUserAgents = rw.BlockUserAgents
		}
		if len(rw.AllowUserAgents) > 0 {
			fileCfg.AllowUserAgents = rw.AllowUserAgents
		}
		if len(rw.HoneypotTrapPaths) > 0 {
			fileCfg.HoneypotTrapPaths = rw.HoneypotTrapPaths
		}
		if rw.isExplicit("enable_robots_txt_honeypot", "enableRobotsTxtHoneypot") || (!hasExplicit && rw.EnableRobotsTxtHoneypot) {
			fileCfg.EnableRobotsTxtHoneypot = rw.EnableRobotsTxtHoneypot
		}
		if rw.isExplicit("robots_txt_honeypot_secret", "robotsTxtHoneypotSecret") || (!hasExplicit && rw.RobotsTxtHoneypotSecret != "") {
			fileCfg.RobotsTxtHoneypotSecret = rw.RobotsTxtHoneypotSecret
		}
		if rw.TrapBanDuration != "" {
			fileCfg.TrapBanDuration = rw.TrapBanDuration
		}
		if rw.isExplicit("verify_search_engine_bots", "verifySearchEngineBots") || (!hasExplicit && rw.VerifySearchEngineBots) {
			fileCfg.VerifySearchEngineBots = rw.VerifySearchEngineBots
		}
		if rw.isExplicit("detect_browser_impersonation", "detectBrowserImpersonation") || (!hasExplicit && rw.DetectBrowserImpersonation) {
			fileCfg.DetectBrowserImpersonation = rw.DetectBrowserImpersonation
		}
		if rw.isExplicit("block_script_clients", "blockScriptClients") || (!hasExplicit && rw.BlockScriptClients) {
			fileCfg.BlockScriptClients = rw.BlockScriptClients
		}
		if rw.isExplicit("block_cloud_hosts", "blockCloudHosts") || (!hasExplicit && rw.BlockCloudHosts) {
			fileCfg.BlockCloudHosts = rw.BlockCloudHosts
		}
		if len(rw.AllowedIPs) > 0 {
			fileCfg.AllowedIPs = rw.AllowedIPs
		}
		if len(rw.TrustedProxies) > 0 {
			fileCfg.TrustedProxies = rw.TrustedProxies
		}
		if rw.isExplicit("methods") || (!hasExplicit && len(rw.Methods) > 0) {
			fileCfg.Methods = rw.Methods
		}
		if len(rw.CheckHeaders) > 0 {
			fileCfg.CheckHeaders = rw.CheckHeaders
		}
		if len(rw.CheckBodyPatterns) > 0 {
			fileCfg.CheckBodyPatterns = rw.CheckBodyPatterns
		}
		if rw.CheckBodyMaxBytes > 0 {
			fileCfg.CheckBodyMaxBytes = rw.CheckBodyMaxBytes
		}
		if rw.StatusCode > 0 {
			fileCfg.StatusCode = rw.StatusCode
			if fileCfg.Response != nil {
				fileCfg.Response.StatusCode = rw.StatusCode
			}
		}
		if rw.CustomResponseText != "" {
			fileCfg.CustomResponseText = rw.CustomResponseText
		}
		if rw.Mode != "" {
			fileCfg.Mode = rw.Mode
			if fileCfg.Response != nil {
				fileCfg.Response.Mode = rw.Mode
			}
		}
		if rw.isExplicit("response") || (!hasExplicit && rw.Response != nil) {
			fileCfg.Response = rw.Response
		}
		if rw.isExplicit("redirect_url") && rw.Response != nil && rw.Response.RedirectURL != "" {
			if fileCfg.Response == nil {
				fileCfg.Response = DefaultResponseConfig()
			}
			fileCfg.Response.RedirectURL = rw.Response.RedirectURL
		}
		if rw.isExplicit("proxy_url") && rw.Response != nil && rw.Response.ProxyURL != "" {
			if fileCfg.Response == nil {
				fileCfg.Response = DefaultResponseConfig()
			}
			fileCfg.Response.ProxyURL = rw.Response.ProxyURL
		}
		if rw.isExplicit("check_query") || (!hasExplicit && rw.CheckQuery) {
			fileCfg.CheckQuery = rw.CheckQuery
		}
		if rw.isExplicit("check_body") || (!hasExplicit && rw.CheckBody) {
			fileCfg.CheckBody = rw.CheckBody
		}
		if rw.isExplicit("debug") || (!hasExplicit && rw.Debug) {
			fileCfg.Debug = rw.Debug
		}
		if rw.isExplicit("security_log") || (!hasExplicit && rw.SecurityLog) {
			fileCfg.SecurityLog = rw.SecurityLog
		}

		fileCfg.logger = rw.logger
		fileCfg.ConfigFile = rw.ConfigFile
		*rw = fileCfg
	} else {
		lvl := rw.BotDefenseLevel
		if lvl == "" {
			lvl = rw.BotDefenseLevelCamel
		}
		if lvl != "" {
			rw.applyBotDefense(lvl)
		}
	}

	if rw.Response == nil {
		rw.Response = DefaultResponseConfig()
	}

	// Response action is configured via mode
	if rw.Mode != "" {
		rw.Response.Mode = rw.Mode
	}
	cleanMode := strings.ToLower(strings.ReplaceAll(rw.Response.Mode, "_", ""))
	if cleanMode == "silentdrop" || cleanMode == "drop" {
		rw.Response.Mode = "silentDrop"
	}

	// Initialize Methods Filter (defaults to ["GET"], or common verbs when body inspection is enabled)
	methodsMap := make(map[string]struct{})
	if len(rw.Methods) == 0 {
		methodsMap["GET"] = struct{}{}
		if rw.CheckBody || len(rw.CheckBodyPatterns) > 0 {
			methodsMap["POST"] = struct{}{}
			methodsMap["PUT"] = struct{}{}
			methodsMap["PATCH"] = struct{}{}
			methodsMap["DELETE"] = struct{}{}
		}
	} else if len(rw.Methods) == 1 && strings.EqualFold(rw.Methods[0], "GET") && (rw.CheckBody || len(rw.CheckBodyPatterns) > 0) {
		methodsMap["GET"] = struct{}{}
		methodsMap["POST"] = struct{}{}
		methodsMap["PUT"] = struct{}{}
		methodsMap["PATCH"] = struct{}{}
		methodsMap["DELETE"] = struct{}{}
	} else {
		for _, m := range rw.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				methodsMap[m] = struct{}{}
			}
		}
		if len(methodsMap) == 0 {
			methodsMap["GET"] = struct{}{}
			if rw.CheckBody || len(rw.CheckBodyPatterns) > 0 {
				methodsMap["POST"] = struct{}{}
				methodsMap["PUT"] = struct{}{}
				methodsMap["PATCH"] = struct{}{}
				methodsMap["DELETE"] = struct{}{}
			}
		}
	}
	rw.methods = methodsMap

	// 1. Compile Block Patterns
	var allBlockPatterns []string
	if rw.EnableDefaultPatterns {
		allBlockPatterns = append(allBlockPatterns, DefaultBlockPatterns...)
	}
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

	// 3. Compile Body Block Patterns
	if rw.CheckBodyMaxBytes <= 0 {
		rw.CheckBodyMaxBytes = 64 * 1024 // 64 KB safety limit
	}
	rw.compiledBody = make([]*regexp.Regexp, 0, len(rw.CheckBodyPatterns))
	for _, p := range rw.CheckBodyPatterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("routewarden: invalid check_body regex %q: %w", p, err)
		}
		rw.compiledBody = append(rw.compiledBody, re)
	}

	// 3b. Compile User-Agent Block & Allow Patterns
	rw.compiledBlockUA = make([]*regexp.Regexp, 0, len(rw.BlockUserAgents))
	for _, p := range rw.BlockUserAgents {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("routewarden: invalid block_user_agents regex %q: %w", p, err)
		}
		rw.compiledBlockUA = append(rw.compiledBlockUA, re)
	}

	rw.compiledAllowUA = make([]*regexp.Regexp, 0, len(rw.AllowUserAgents))
	for _, p := range rw.AllowUserAgents {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("routewarden: invalid allow_user_agents regex %q: %w", p, err)
		}
		rw.compiledAllowUA = append(rw.compiledAllowUA, re)
	}

	// 4. Initialize IP Filter
	if len(rw.AllowedIPs) > 0 || len(rw.TrustedProxies) > 0 || len(rw.AllowedASNs) > 0 || len(rw.BlockedASNs) > 0 || rw.BlockCloudHosts {
		filter, err := NewIPFilter(rw.AllowedIPs, rw.TrustedProxies)
		if err != nil {
			return fmt.Errorf("routewarden: invalid ip filter config: %w", err)
		}
		filter.asn, err = NewASNFilterEx(rw.AllowedASNs, rw.BlockedASNs, rw.ASNDB, rw.BlockCloudHosts)
		if err != nil {
			return err
		}
		rw.ipFilter = filter
	}

	// 5. Initialize Response Handler
	isSilentDrop := strings.EqualFold(rw.Response.Mode, "silentdrop") || strings.EqualFold(rw.Response.Mode, "silent_drop") || strings.EqualFold(rw.Response.Mode, "drop")
	respHandler, err := NewResponseHandler(rw.Response, rw.StatusCode, rw.CustomResponseText, isSilentDrop)
	if err != nil {
		return fmt.Errorf("routewarden: invalid response config: %w", err)
	}
	respHandler.SetLogger(rw.logger, rw.Debug)
	rw.responseHandler = respHandler

	// 6. Initialize Honeypot Spider Trap Ban Table
	rw.parsedBanDuration = ParseBanDuration(rw.TrapBanDuration)
	if len(rw.HoneypotTrapPaths) > 0 || rw.EnableRobotsTxtHoneypot {
		rw.banTable = NewBanTable(10000)
	}

	// 7. Initialize Search Engine FCrDNS Verifier
	if rw.VerifySearchEngineBots {
		rw.fcrdnsVerifier = NewFCrDNSVerifier(6*time.Hour, 500*time.Millisecond)
	}

	if rw.Debug && rw.logger != nil {
		rw.logger.Debug("routewarden: provisioned successfully",
			zap.Int("compiled_block_patterns", len(rw.compiledBlock)),
			zap.Int("compiled_allow_patterns", len(rw.compiledAllow)),
			zap.Int("allowed_ips", len(rw.AllowedIPs)),
			zap.Int("trusted_proxies", len(rw.TrustedProxies)),
			zap.Strings("methods", rw.Methods),
			zap.Bool("check_query", rw.CheckQuery),
			zap.String("response_mode", rw.Response.Mode),
		)
	}

	return nil
}

// Validate ensures the configuration is valid.
func (rw *RouteWarden) Validate() error {
	if rw.StatusCode != 0 && (rw.StatusCode < 100 || rw.StatusCode > 599) {
		return fmt.Errorf("routewarden: statusCode must be between 100 and 599, got %d", rw.StatusCode)
	}
	if rw.Response != nil && rw.Response.StatusCode != 0 {
		if rw.Response.StatusCode < 100 || rw.Response.StatusCode > 599 {
			return fmt.Errorf("routewarden: statusCode must be between 100 and 599, got %d", rw.Response.StatusCode)
		}
	}
	return nil
}

// SetFCrDNSLookupFuncs overrides the DNS lookup functions for testing purposes.
func (rw *RouteWarden) SetFCrDNSLookupFuncs(
	lookupAddr func(ctx context.Context, addr string) ([]string, error),
	lookupIP func(ctx context.Context, host string) ([]net.IP, error),
) {
	if rw.fcrdnsVerifier != nil {
		rw.fcrdnsVerifier.lookupAddr = lookupAddr
		rw.fcrdnsVerifier.lookupIP = lookupIP
	}
}

func (rw *RouteWarden) extractClientIP(req *http.Request) string {
	if rw.ipFilter != nil {
		return rw.ipFilter.ExtractClientIP(req)
	}
	return ExtractClientIP(req)
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (rw *RouteWarden) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	if !rw.Enabled {
		return next.ServeHTTP(w, req)
	}

	// Only inspect requests whose HTTP method matches configured verbs (default: GET)
	if len(rw.methods) > 0 {
		_, hasWildcard := rw.methods["*"]
		_, hasAll := rw.methods["ALL"]
		_, matchesMethod := rw.methods[strings.ToUpper(req.Method)]
		if !hasWildcard && !hasAll && !matchesMethod {
			if rw.Debug && rw.logger != nil {
				rw.logger.Debug("routewarden: method not inspected",
					zap.String("method", req.Method),
					zap.String("path", req.URL.Path),
				)
			}
			return next.ServeHTTP(w, req)
		}
	}


	// Stage 1: IP Whitelist bypass
	if rw.ipFilter != nil {
		clientIP := rw.extractClientIP(req)
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

	// Stage 1b: Blocked ASN check
	if rw.ipFilter != nil {
		if isBlockedASN, asnNum := rw.ipFilter.IsBlockedASN(req); isBlockedASN {
			clientIP := rw.extractClientIP(req)
			rw.logSecurityEvent(req, fmt.Sprintf("AS%d", asnNum), fmt.Sprintf("AS%d", asnNum), "asn_blocked")
			if rw.logger != nil {
				rw.logger.Warn("routewarden: blocked client from denied ASN",
					zap.String("client_ip", clientIP),
					zap.Uint32("asn", asnNum),
				)
			}
			if rw.responseHandler != nil {
				rw.responseHandler.ServeBlockedRequest(w, req)
			} else {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Access Denied\n"))
			}
			return nil
		}
	}

	// Stage 1c: Active Ban Table Check
	clientIP := rw.extractClientIP(req)
	if rw.banTable != nil && rw.banTable.IsBanned(clientIP) {
		rw.logSecurityEvent(req, clientIP, "active_ban", "ip_banned")
		if rw.logger != nil {
			rw.logger.Warn("routewarden: blocked client from active ban table",
				zap.String("client_ip", clientIP),
			)
		}
		if rw.responseHandler != nil {
			rw.responseHandler.ServeBlockedRequest(w, req)
		} else {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied\n"))
		}
		return nil
	}

	// Check PoW solution cookie (__rw_pow) or header (X-RW-PoW)
	powToken := extractPoWToken(req)
	isPoWValid := false
	if powToken != "" && rw.responseHandler != nil && rw.responseHandler.config != nil {
		secret := rw.responseHandler.config.PoWSecret
		if secret == "" {
			secret = DefaultPoWSecret
		}
		timeout := rw.responseHandler.config.PoWTimeoutSeconds
		if timeout <= 0 {
			timeout = DefaultPoWTimeoutSeconds
		}
		isPoWValid, _ = VerifyPoWSolution(clientIP, secret, powToken, timeout, time.Now())
	}

	serveBlock := func(target, pattern, reason string) error {
		if isPoWValid {
			if rw.Debug && rw.logger != nil {
				rw.logger.Debug("routewarden: client PoW verified, bypassing block",
					zap.String("client_ip", clientIP),
					zap.String("pattern", pattern),
					zap.String("reason", reason),
				)
			}
			return rw.forwardRequest(w, req, next)
		}
		rw.logSecurityEvent(req, target, pattern, reason)
		if rw.responseHandler != nil {
			rw.responseHandler.ServeBlockedRequest(w, req)
		} else {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied\n"))
		}
		return nil
	}

	// Stage 1d: User-Agent & AI Bot Inspection
	ua := req.UserAgent()
	uaAllowed := false
	for _, re := range rw.compiledAllowUA {
		if re.MatchString(ua) {
			uaAllowed = true
			break
		}
	}

	if !uaAllowed {
		// Search engine bot impersonation verification (FCrDNS)
		if rw.VerifySearchEngineBots && rw.fcrdnsVerifier != nil {
			if claimsBot, engine := DetectSearchEngineBot(ua); claimsBot {
				if !rw.fcrdnsVerifier.Verify(req.Context(), clientIP, engine) {
					if rw.logger != nil {
						rw.logger.Warn("routewarden: blocked spoofed search engine bot",
							zap.String("client_ip", clientIP),
							zap.String("user_agent", ua),
							zap.String("claimed_engine", string(engine)),
						)
					}
					return serveBlock(ua, string(engine)+"_spoofed", "search_engine_spoofed")
				}
				uaAllowed = true
			}
		}
	}

	if !uaAllowed {
		uaBlocked := false
		uaPattern := ""
		uaReason := ""

		for _, re := range rw.compiledBlockUA {
			if re.MatchString(ua) {
				uaBlocked = true
				uaPattern = re.String()
				uaReason = "user_agent_blocked"
				break
			}
		}

		if !uaBlocked && rw.BlockAIBots {
			if matched, botType := MatchAIBot(ua, rw.AIBotProfile); matched {
				uaBlocked = true
				uaPattern = botType
				uaReason = "ai_bot_blocked"
			}
		}

		if !uaBlocked && rw.DetectBrowserImpersonation {
			if isSpoofed, reason := DetectBrowserImpersonation(ua, req.Header); isSpoofed {
				uaBlocked = true
				uaPattern = reason
				uaReason = "browser_spoofed"
			}
		}

		if !uaBlocked && rw.BlockScriptClients {
			if isScript, clientType := DetectScriptClient(ua, req.Header); isScript {
				uaBlocked = true
				uaPattern = clientType
				uaReason = "script_client_blocked"
			}
		}

		if uaBlocked {
			clientIP := rw.extractClientIP(req)
			if rw.logger != nil {
				rw.logger.Warn("routewarden: blocked bot or crawler user agent",
					zap.String("client_ip", clientIP),
					zap.String("user_agent", ua),
					zap.String("pattern", uaPattern),
					zap.String("reason", uaReason),
				)
			}
			return serveBlock(ua, uaPattern, uaReason)
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

	// Stage 2b: Honeypot Spider Trap Check (static and dynamic robots.txt traps)
	var activeTraps []string
	if len(rw.HoneypotTrapPaths) > 0 {
		activeTraps = append(activeTraps, rw.HoneypotTrapPaths...)
	}
	if rw.EnableRobotsTxtHoneypot {
		_, dynPrefixes := GetActiveRobotsHoneypotTraps(rw.RobotsTxtHoneypotSecret, time.Now())
		activeTraps = append(activeTraps, dynPrefixes...)
	}

	if len(activeTraps) > 0 {
		for _, candPath := range candidatePaths {
			for _, trapPath := range activeTraps {
				cleanTrap := strings.TrimSpace(trapPath)
				if cleanTrap != "" && !strings.HasPrefix(cleanTrap, "/") {
					cleanTrap = "/" + cleanTrap
				}
				baseTrap := strings.TrimRight(cleanTrap, "/")
				if baseTrap == "" {
					continue
				}
				prefixTrap := baseTrap + "/"
				lowerCand := strings.ToLower(candPath)
				lowerBase := strings.ToLower(baseTrap)
				lowerPrefix := strings.ToLower(prefixTrap)
				if lowerCand == lowerBase || strings.HasPrefix(lowerCand, lowerPrefix) {
					if rw.banTable != nil && clientIP != "" {
						rw.banTable.Ban(clientIP, rw.parsedBanDuration)
					}
					rw.logSecurityEvent(req, candPath, cleanTrap, "honeypot_trap_triggered")
					if rw.logger != nil {
						rw.logger.Warn("routewarden: honeypot spider trap triggered, client IP banned",
							zap.String("client_ip", clientIP),
							zap.String("trap_path", cleanTrap),
							zap.String("matched_path", candPath),
							zap.Duration("ban_duration", rw.parsedBanDuration),
						)
					}
					if rw.responseHandler != nil {
						rw.responseHandler.ServeBlockedRequest(w, req)
					} else {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte("Access Denied\n"))
					}
					return nil
				}
			}
		}
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
				return rw.forwardRequest(w, req, next)
			}
		}
	}

	// Datacenter & Cloud Hosting IP Classifier
	if !uaAllowed && rw.BlockCloudHosts && rw.ipFilter != nil && rw.ipFilter.asn != nil {
		if isCloud, cloudASN, provider := rw.ipFilter.asn.IsCloudHost(clientIP); isCloud {
			reason := "cloud_host_blocked"
			if reBrowserLike.MatchString(ua) {
				reason = "datacenter_browser_impersonation"
			}
			matchedPattern := fmt.Sprintf("AS%d (%s)", cloudASN, provider)
			if rw.logger != nil {
				rw.logger.Warn("routewarden: client blocked by cloud host classifier",
					zap.String("client_ip", clientIP),
					zap.Uint32("asn", cloudASN),
					zap.String("provider", provider),
					zap.String("reason", reason),
				)
			}
			return serveBlock(clientIP, matchedPattern, reason)
		}
	}

	// Stage 4: Block Patterns Match
	var blockedByPattern string
	var blockedTarget string
	var blockedReason string
	isBlocked := false

	for _, p := range candidatePaths {
		for _, re := range rw.compiledBlock {
			if re.MatchString(p) {
				isBlocked = true
				blockedByPattern = re.String()
				blockedTarget = p
				blockedReason = "path_blocked"
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
		unescapedQuery := lenientQueryUnescape(req.URL.RawQuery)

		queryCandidates := []string{req.URL.RawQuery, unescapedQuery}
		parsedQuery, _ := url.ParseQuery(req.URL.RawQuery)
		for key, vals := range parsedQuery {
			queryCandidates = append(queryCandidates, key)
			queryCandidates = append(queryCandidates, ExtractCandidatePaths("", key, key)...)
			for _, v := range vals {
				queryCandidates = append(queryCandidates, v)
				queryCandidates = append(queryCandidates, ExtractCandidatePaths(v, v, v)...)
			}
		}
		// Also split raw and unescaped query strings on '&' and ';' to catch keys/values even when
		// malformed encodings, semicolons, or encoded delimiters (%26, %3b) cause ParseQuery to error
		queriesToParse := []string{req.URL.RawQuery}
		if unescapedQuery != req.URL.RawQuery {
			queriesToParse = append(queriesToParse, unescapedQuery)
		}
		for _, qStr := range queriesToParse {
			for _, pair := range strings.FieldsFunc(qStr, func(r rune) bool { return r == '&' || r == ';' }) {
				if k, v, ok := strings.Cut(pair, "="); ok {
					queryCandidates = append(queryCandidates, k, v)
					queryCandidates = append(queryCandidates, ExtractCandidatePaths("", k, k)...)
					queryCandidates = append(queryCandidates, ExtractCandidatePaths("", v, v)...)
				} else if pair != "" {
					queryCandidates = append(queryCandidates, pair)
					queryCandidates = append(queryCandidates, ExtractCandidatePaths("", pair, pair)...)
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
					blockedTarget = unescapedQuery
					blockedReason = "query_blocked"
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

	// Optional: Check Forwarded/Rewrite Headers
	if !isBlocked && len(rw.CheckHeaders) > 0 {
		for _, headerName := range rw.CheckHeaders {
			for _, rawHeaderVal := range req.Header.Values(headerName) {
				rawHeaderVal = strings.TrimSpace(rawHeaderVal)
				if rawHeaderVal == "" {
					continue
				}
				headerVals := []string{rawHeaderVal}
				if strings.HasPrefix(rawHeaderVal, "\"") && strings.HasSuffix(rawHeaderVal, "\"") && len(rawHeaderVal) >= 2 {
					unquoted := strings.TrimSpace(rawHeaderVal[1 : len(rawHeaderVal)-1])
					if unquoted != "" && unquoted != rawHeaderVal {
						headerVals = append(headerVals, unquoted)
					}
				} else if strings.HasPrefix(rawHeaderVal, "'") && strings.HasSuffix(rawHeaderVal, "'") && len(rawHeaderVal) >= 2 {
					unquoted := strings.TrimSpace(rawHeaderVal[1 : len(rawHeaderVal)-1])
					if unquoted != "" && unquoted != rawHeaderVal {
						headerVals = append(headerVals, unquoted)
					}
				}
				if strings.Contains(rawHeaderVal, ",") {
					for _, part := range strings.Split(rawHeaderVal, ",") {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(part, "\"") && strings.HasSuffix(part, "\"") && len(part) >= 2 {
							part = strings.TrimSpace(part[1 : len(part)-1])
						} else if strings.HasPrefix(part, "'") && strings.HasSuffix(part, "'") && len(part) >= 2 {
							part = strings.TrimSpace(part[1 : len(part)-1])
						}
						if part != "" {
							headerVals = append(headerVals, part)
						}
					}
				}

				for _, headerVal := range headerVals {
					headerCandidates := append([]string{headerVal}, ExtractCandidatePaths("", headerVal, headerVal)...)
					for _, hc := range headerCandidates {
						for _, re := range rw.compiledBlock {
							if re.MatchString(hc) {
								isBlocked = true
								blockedByPattern = re.String()
								blockedTarget = rawHeaderVal
								blockedReason = "header_blocked"
								if rw.Debug && rw.logger != nil {
									rw.logger.Debug("routewarden: header candidate matched block pattern",
										zap.String("header", headerName),
										zap.String("candidate_value", hc),
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
					if isBlocked {
						break
					}
				}
				if isBlocked {
					break
				}
			}
			if isBlocked {
				break
			}
		}
	}

	// Optional: Check Request Body (e.g. POST form payloads, OAuth grants, JSON params)
	if !isBlocked && (rw.CheckBody || len(rw.compiledBody) > 0) && req.Body != nil && req.Body != http.NoBody {
		maxBytes := rw.CheckBodyMaxBytes
		if maxBytes <= 0 {
			maxBytes = 64 * 1024
		}

		origBody := req.Body
		bodyBytes, _ := io.ReadAll(io.LimitReader(origBody, maxBytes))
		if len(bodyBytes) > 0 {
			// Re-assign a new ReadCloser so downstream handlers (reverse_proxy) can still read the entire body
			req.Body = &bodyReadCloser{
				Reader: io.MultiReader(bytes.NewReader(bodyBytes), origBody),
				Closer: origBody,
			}

			bodyStr := string(bodyBytes)
			unescapedBody := lenientQueryUnescape(bodyStr)

			bodyCandidates := []string{bodyStr, unescapedBody}

			// Form urlencoded parameters extraction (&, ;)
			if parsedValues, err := url.ParseQuery(bodyStr); err == nil && len(parsedValues) > 0 {
				for k, vs := range parsedValues {
					bodyCandidates = append(bodyCandidates, k)
					bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", k, k)...)
					for _, v := range vs {
						bodyCandidates = append(bodyCandidates, v)
						bodyCandidates = append(bodyCandidates, ExtractCandidatePaths(v, v, v)...)
					}
				}
			}
			bodiesToParse := []string{bodyStr}
			if unescapedBody != bodyStr {
				bodiesToParse = append(bodiesToParse, unescapedBody)
			}
			for _, bStr := range bodiesToParse {
				for _, pair := range strings.FieldsFunc(bStr, func(r rune) bool { return r == '&' || r == ';' }) {
					if k, v, ok := strings.Cut(pair, "="); ok {
						bodyCandidates = append(bodyCandidates, k, v)
						bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", k, k)...)
						bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", v, v)...)
					}
				}
			}

			// JSON payload string values extraction
			trimmedBody := strings.TrimSpace(bodyStr)
			if (strings.HasPrefix(trimmedBody, "{") && strings.HasSuffix(trimmedBody, "}")) ||
				(strings.HasPrefix(trimmedBody, "[") && strings.HasSuffix(trimmedBody, "]")) {
				var jsonVal any
				if err := json.Unmarshal([]byte(trimmedBody), &jsonVal); err == nil {
					var extractJSON func(v any)
					extractJSON = func(v any) {
						switch val := v.(type) {
						case string:
							bodyCandidates = append(bodyCandidates, val)
							bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", val, val)...)
						case []any:
							for _, item := range val {
								extractJSON(item)
							}
						case map[string]any:
							for k, item := range val {
								bodyCandidates = append(bodyCandidates, k)
								bodyCandidates = append(bodyCandidates, ExtractCandidatePaths("", k, k)...)
								extractJSON(item)
							}
						}
					}
					extractJSON(jsonVal)
				}
			}

			// If specific CheckBodyPatterns were defined, check against them:
			patternsToCheck := rw.compiledBody
			// If CheckBody is enabled but no custom CheckBodyPatterns were provided, match against compiledBlock:
			if len(patternsToCheck) == 0 {
				patternsToCheck = rw.compiledBlock
			}

			if rw.Debug && rw.logger != nil {
				rw.logger.Debug("routewarden: checking request body",
					zap.Int("body_len", len(bodyBytes)),
					zap.Int("patterns_count", len(patternsToCheck)),
				)
			}

			for _, bc := range bodyCandidates {
				for _, re := range patternsToCheck {
					if re.MatchString(bc) {
						isBlocked = true
						blockedByPattern = re.String()
						blockedTarget = "[body payload]"
						blockedReason = "body_blocked"
						if rw.Debug && rw.logger != nil {
							rw.logger.Debug("routewarden: body candidate matched block pattern",
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
		} else {
			// Restore original body without unnecessary wrapping
			req.Body = origBody
		}
	}

	if isBlocked {
		respMode := "text"
		if rw.responseHandler != nil && rw.responseHandler.config != nil && rw.responseHandler.config.Mode != "" {
			respMode = rw.responseHandler.config.Mode
		} else if rw.Response != nil && rw.Response.Mode != "" {
			respMode = rw.Response.Mode
		} else if rw.Mode != "" {
			respMode = rw.Mode
		}

		if rw.logger != nil {
			clientIP := rw.extractClientIP(req)
			rw.logger.Warn("routewarden: blocked sensitive request",
				zap.String("client_ip", clientIP),
				zap.String("remote_addr", req.RemoteAddr),
				zap.String("path", req.URL.Path),
				zap.String("pattern", blockedByPattern),
				zap.String("mode", respMode),
			)
		}
		return serveBlock(blockedTarget, blockedByPattern, blockedReason)
	}

	if rw.Debug && rw.logger != nil {
		rw.logger.Debug("routewarden: request passed inspection",
			zap.String("path", req.URL.Path),
			zap.String("method", req.Method),
		)
	}

	return rw.forwardRequest(w, req, next)
}

func (rw *RouteWarden) forwardRequest(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	if rw.EnableRobotsTxtHoneypot && IsRobotsTxtPath(req.URL.Path) && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
		buf := &robotsResponseBuffer{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			header:         make(http.Header),
		}
		err := next.ServeHTTP(buf, req)

		activeTrap, _ := GetActiveRobotsHoneypotTraps(rw.RobotsTxtHoneypotSecret, time.Now())
		var finalBody []byte
		if buf.statusCode == http.StatusNotFound {
			buf.statusCode = http.StatusOK
			finalBody = InjectRobotsTxtTrap(nil, activeTrap)
		} else if buf.statusCode >= 200 && buf.statusCode < 300 {
			finalBody = InjectRobotsTxtTrap(buf.buf.Bytes(), activeTrap)
		} else {
			buf.flushOriginal()
			return err
		}

		for k, vv := range buf.header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(buf.statusCode)
		_, writeErr := w.Write(finalBody)
		if err != nil {
			return err
		}
		return writeErr
	}

	return next.ServeHTTP(w, req)
}

// logSecurityEvent emits structured Zap warnings and standard CrowdSec JSON logs on stdout.
func (rw *RouteWarden) logSecurityEvent(r *http.Request, matchedTarget string, pattern string, reason string) {
	if !rw.SecurityLog {
		return
	}
	mode := "text"
	statusCode := http.StatusForbidden
	if rw.responseHandler != nil {
		if rw.responseHandler.silentDrop {
			mode = "silentDrop"
		} else if rw.responseHandler.config != nil && rw.responseHandler.config.Mode != "" {
			mode = rw.responseHandler.config.Mode
		}
		statusCode = rw.responseHandler.EffectiveStatusCode()
	} else if rw.Response != nil {
		if rw.Response.Mode != "" {
			mode = rw.Response.Mode
		}
		if rw.Response.StatusCode != 0 {
			statusCode = rw.Response.StatusCode
		}
	}
	clientIP := rw.extractClientIP(r)

	verdict := "BLOCK"
	cleanMode := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mode), "_", ""))
	switch cleanMode {
	case "tarpit", "markovtarpit":
		verdict = "TARPIT"
	case "captcha", "ratelimitchallenge", "challenge":
		verdict = "CHALLENGE"
	}

	// If using Caddy's zap logger:
	if rw.logger != nil {
		rw.logger.Warn("routewarden_block",
			zap.String("type", "routewarden_block"),
			zap.String("level", "warn"),
			zap.String("verdict", verdict),
			zap.Int("status_code", statusCode),
			zap.String("client_ip", clientIP),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("matched_target", matchedTarget),
			zap.String("request_uri", r.RequestURI),
			zap.String("pattern", pattern),
			zap.String("matched_pattern", pattern),
			zap.String("action", mode),
			zap.String("reason", reason),
			zap.String("user_agent", r.UserAgent()),
		)
	}

	// Also emit raw JSON to stdout so standard CrowdSec parsers pick it up identically:
	event := map[string]interface{}{
		"type":            "routewarden_block",
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"level":           "warn",
		"verdict":         verdict,
		"plugin":          "caddy-warden",
		"client_ip":       clientIP,
		"method":          r.Method,
		"path":            r.URL.Path,
		"matched_target":  matchedTarget,
		"request_uri":     r.RequestURI,
		"pattern":         pattern,
		"matched_pattern": pattern,
		"action":          mode,
		"status_code":     statusCode,
		"reason":          reason,
		"user_agent":      r.UserAgent(),
	}
	if data, err := json.Marshal(event); err == nil {
		fmt.Fprintf(os.Stdout, "%s\n", string(data))
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*RouteWarden)(nil)
	_ caddy.Validator             = (*RouteWarden)(nil)
	_ caddyhttp.MiddlewareHandler = (*RouteWarden)(nil)
	_ caddyfile.Unmarshaler       = (*RouteWarden)(nil)
)

// bodyReadCloser combines an io.Reader and io.Closer to preserve the underlying
// connection/body closer when request bodies are buffered and replayed.
type bodyReadCloser struct {
	io.Reader
	io.Closer
}

func (b *bodyReadCloser) Close() error {
	if b.Closer != nil {
		return b.Closer.Close()
	}
	return nil
}

func applyBotDefenseLevel(level string, blockAIBots *bool, aiBotProfile *string, detectBrowser *bool, blockScripts *bool, verifySearch *bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "light", "relaxed":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "train_only"
		}
		*blockScripts = true
		*verifySearch = true
	case "standard", "moderate":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "train_only"
		}
		*blockScripts = true
		*detectBrowser = true
		*verifySearch = true
	case "strict":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "all"
		}
		*blockScripts = true
		*detectBrowser = true
		*verifySearch = true
	case "aggressive", "paranoia":
		*blockAIBots = true
		if *aiBotProfile == "" {
			*aiBotProfile = "aggressive"
		}
		*blockScripts = true
		*detectBrowser = true
		*verifySearch = true
	}
}

func (rw *RouteWarden) applyBotDefense(level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "light", "relaxed":
		if !rw.isExplicit("block_ai_bots", "blockAIBots") {
			rw.BlockAIBots = true
		}
		if !rw.isExplicit("ai_bot_profile", "aiBotProfile") && rw.AIBotProfile == "" {
			rw.AIBotProfile = "train_only"
		}
		if !rw.isExplicit("block_script_clients", "blockScriptClients") {
			rw.BlockScriptClients = true
		}
		if !rw.isExplicit("verify_search_engine_bots", "verifySearchEngineBots") {
			rw.VerifySearchEngineBots = true
		}
	case "standard", "moderate":
		if !rw.isExplicit("block_ai_bots", "blockAIBots") {
			rw.BlockAIBots = true
		}
		if !rw.isExplicit("ai_bot_profile", "aiBotProfile") && rw.AIBotProfile == "" {
			rw.AIBotProfile = "train_only"
		}
		if !rw.isExplicit("block_script_clients", "blockScriptClients") {
			rw.BlockScriptClients = true
		}
		if !rw.isExplicit("detect_browser_impersonation", "detectBrowserImpersonation") {
			rw.DetectBrowserImpersonation = true
		}
		if !rw.isExplicit("verify_search_engine_bots", "verifySearchEngineBots") {
			rw.VerifySearchEngineBots = true
		}
	case "strict":
		if !rw.isExplicit("block_ai_bots", "blockAIBots") {
			rw.BlockAIBots = true
		}
		if !rw.isExplicit("ai_bot_profile", "aiBotProfile") && rw.AIBotProfile == "" {
			rw.AIBotProfile = "all"
		}
		if !rw.isExplicit("block_script_clients", "blockScriptClients") {
			rw.BlockScriptClients = true
		}
		if !rw.isExplicit("detect_browser_impersonation", "detectBrowserImpersonation") {
			rw.DetectBrowserImpersonation = true
		}
		if !rw.isExplicit("verify_search_engine_bots", "verifySearchEngineBots") {
			rw.VerifySearchEngineBots = true
		}
	case "aggressive", "paranoia":
		if !rw.isExplicit("block_ai_bots", "blockAIBots") {
			rw.BlockAIBots = true
		}
		if !rw.isExplicit("ai_bot_profile", "aiBotProfile") && rw.AIBotProfile == "" {
			rw.AIBotProfile = "aggressive"
		}
		if !rw.isExplicit("block_script_clients", "blockScriptClients") {
			rw.BlockScriptClients = true
		}
		if !rw.isExplicit("detect_browser_impersonation", "detectBrowserImpersonation") {
			rw.DetectBrowserImpersonation = true
		}
		if !rw.isExplicit("verify_search_engine_bots", "verifySearchEngineBots") {
			rw.VerifySearchEngineBots = true
		}
	}
}
