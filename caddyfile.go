package caddywarden

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	rw := &RouteWarden{
		Enabled:                    true,
		EnableDefaultPatterns:      true,
		EnableDefaultAllowPatterns: true,
		Methods:                    []string{"GET"},
		Response:                   DefaultResponseConfig(),
	}
	err := rw.UnmarshalCaddyfile(h.Dispenser)
	return rw, err
}

func parseBoolArg(d *caddyfile.Dispenser, defaultVal bool) bool {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return defaultVal
	}
	if b, err := strconv.ParseBool(args[0]); err == nil {
		return b
	}
	val := strings.ToLower(args[0])
	return val == "yes" || val == "on"
}

func (rw *RouteWarden) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	rw.Enabled = true
	rw.EnableDefaultPatterns = true
	rw.EnableDefaultAllowPatterns = true
	if rw.Response == nil {
		rw.Response = DefaultResponseConfig()
	}

	var customMethods []string

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "enabled":
				rw.Enabled = parseBoolArg(d, true)

			case "enable_default_patterns":
				rw.EnableDefaultPatterns = parseBoolArg(d, true)

			case "enable_default_allow_patterns":
				rw.EnableDefaultAllowPatterns = parseBoolArg(d, true)

			case "check_query":
				rw.CheckQuery = parseBoolArg(d, true)

			case "check_body":
				rw.CheckBody = parseBoolArg(d, true)

			case "check_body_max_bytes":
				if !d.NextArg() {
					return d.ArgErr()
				}
				bytesVal, err := strconv.ParseInt(d.Val(), 10, 64)
				if err != nil {
					return d.Errf("invalid check_body_max_bytes: %v", err)
				}
				rw.CheckBodyMaxBytes = bytesVal

			case "check_body_patterns":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				rw.CheckBodyPatterns = append(rw.CheckBodyPatterns, args...)

			case "check_headers":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				rw.CheckHeaders = append(rw.CheckHeaders, args...)

			case "debug":
				rw.Debug = true

			case "security_log":
				rw.SecurityLog = parseBoolArg(d, true)

			case "block_patterns":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				rw.BlockPatterns = append(rw.BlockPatterns, args...)

			case "allow_patterns":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				rw.AllowPatterns = append(rw.AllowPatterns, args...)

			case "allowed_ips":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				rw.AllowedIPs = append(rw.AllowedIPs, args...)

			case "trusted_proxies":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				rw.TrustedProxies = append(rw.TrustedProxies, args...)

			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val := d.Val()
				if strings.EqualFold(val, "silent_drop") || strings.EqualFold(val, "silentdrop") || strings.EqualFold(val, "drop") {
					val = "silentDrop"
				}
				rw.Response.Mode = val

			case "status_code":
				if !d.NextArg() {
					return d.ArgErr()
				}
				code, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid status code %s: %v", d.Val(), err)
				}
				rw.StatusCode = code

			case "methods":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				customMethods = append(customMethods, args...)

			case "response":
				for d.NextBlock(1) {
					switch d.Val() {
					case "mode":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val := d.Val()
						if strings.EqualFold(val, "silent_drop") || strings.EqualFold(val, "silentdrop") || strings.EqualFold(val, "drop") {
							val = "silentDrop"
						}
						rw.Response.Mode = val

					case "status_code":
						if !d.NextArg() {
							return d.ArgErr()
						}
						code, err := strconv.Atoi(d.Val())
						if err != nil {
							return d.Errf("invalid response status code %s: %v", d.Val(), err)
						}
						rw.Response.StatusCode = code

					case "content_type":
						if !d.NextArg() {
							return d.ArgErr()
						}
						rw.Response.ContentType = d.Val()

					case "body":
						if !d.NextArg() {
							return d.ArgErr()
						}
						rw.Response.Body = d.Val()

					case "redirect_url":
						if !d.NextArg() {
							return d.ArgErr()
						}
						rw.Response.RedirectURL = d.Val()

					case "proxy_url":
						if !d.NextArg() {
							return d.ArgErr()
						}
						rw.Response.ProxyURL = d.Val()

					case "gzip_bomb_mb":
						if !d.NextArg() {
							return d.ArgErr()
						}
						mb, err := strconv.Atoi(d.Val())
						if err != nil {
							return d.Errf("invalid gzip_bomb_mb %s: %v", d.Val(), err)
						}
						rw.Response.GzipBombMB = mb

					case "retry_after", "retry_after_seconds":
						if !d.NextArg() {
							return d.ArgErr()
						}
						sec, err := strconv.Atoi(d.Val())
						if err != nil {
							return d.Errf("invalid retry_after %s: %v", d.Val(), err)
						}
						rw.Response.RetryAfterSeconds = sec

					case "tarpit_delay_ms":
						if !d.NextArg() {
							return d.ArgErr()
						}
						delay, err := strconv.Atoi(d.Val())
						if err != nil {
							return d.Errf("invalid tarpit_delay_ms %s: %v", d.Val(), err)
						}
						rw.Response.TarpitDelayMs = delay

					case "tarpit_max_duration", "tarpit_max_duration_seconds":
						if !d.NextArg() {
							return d.ArgErr()
						}
						dur, err := strconv.Atoi(d.Val())
						if err != nil {
							return d.Errf("invalid tarpit_max_duration %s: %v", d.Val(), err)
						}
						rw.Response.TarpitMaxDurationSeconds = dur

					case "stream_size_mb":
						if !d.NextArg() {
							return d.ArgErr()
						}
						mb, err := strconv.Atoi(d.Val())
						if err != nil {
							return d.Errf("invalid stream_size_mb %s: %v", d.Val(), err)
						}
						rw.Response.StreamSizeMB = mb

					case "header":
						var key, val string
						if !d.Args(&key, &val) {
							return d.ArgErr()
						}
						if rw.Response.Headers == nil {
							rw.Response.Headers = make(map[string]string)
						}
						rw.Response.Headers[key] = val

					case "captcha":
						if rw.Response.Captcha == nil {
							rw.Response.Captcha = &CaptchaConfig{}
						}
						args := d.RemainingArgs()
						if len(args) >= 2 {
							rw.Response.Captcha.Provider = args[0]
							rw.Response.Captcha.SiteKey = args[1]
							if len(args) >= 3 {
								rw.Response.Captcha.Title = args[2]
							}
						} else if len(args) == 0 {
							for d.NextBlock(2) {
								switch d.Val() {
								case "provider":
									if !d.NextArg() {
										return d.ArgErr()
									}
									rw.Response.Captcha.Provider = d.Val()
								case "site_key":
									if !d.NextArg() {
										return d.ArgErr()
									}
									rw.Response.Captcha.SiteKey = d.Val()
								case "title":
									if !d.NextArg() {
										return d.ArgErr()
									}
									rw.Response.Captcha.Title = d.Val()
								case "template":
									if !d.NextArg() {
										return d.ArgErr()
									}
									rw.Response.Captcha.Template = d.Val()
								default:
									return d.Errf("unrecognized captcha subdirective: %s", d.Val())
								}
							}
							if rw.Response.Captcha.Provider == "" || rw.Response.Captcha.SiteKey == "" {
								return d.Err("captcha requires both provider and site_key")
							}
						} else {
							return d.ArgErr()
						}

					default:
						return d.Errf("unrecognized response subdirective: %s", d.Val())
					}
				}

			default:
				return d.Errf("unrecognized routewarden subdirective: %s", d.Val())
			}
		}
	}
	if len(customMethods) > 0 {
		rw.Methods = customMethods
	} else if len(rw.Methods) == 0 {
		rw.Methods = []string{"GET"}
	}
	return nil
}
