package utils

import "strings"

func DomainToCertCommonName(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 2 {
		return domain
	}

	return "*." + strings.Join(parts[1:], ".")
}
