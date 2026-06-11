package utility

import "net"

// NormalizeIP returns the canonical string form of an IP address.
// Returns "invalid" for unparseable IPs to prevent rate-limit bypass.
func NormalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "invalid"
	}
	return parsed.String()
}
