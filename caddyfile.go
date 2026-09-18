package caddywarden

import (
	"strconv"

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
			case "disable":
				rw.Enabled = false

			case "disable_default_patterns":
				rw.EnableDefaultPatterns = false

			case "disable_default_allow_patterns":
				rw.EnableDefaultAllowPatterns = false

			case "check_query":
				rw.CheckQuery = true

			case "path_patterns", "block_patterns":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				rw.PathPatterns = append(rw.PathPatterns, args...)

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
						rw.Response.Mode = d.Val()

					case "status", "status_code":
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

					case "retry_after":
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

					case "tarpit_max_duration":
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
						var provider, siteKey string
						if !d.Args(&provider, &siteKey) {
							return d.ArgErr()
						}
						if rw.Response.Captcha == nil {
							rw.Response.Captcha = &CaptchaConfig{}
						}
						rw.Response.Captcha.Provider = provider
						rw.Response.Captcha.SiteKey = siteKey
						if d.NextArg() {
							rw.Response.Captcha.Title = d.Val()
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
