package main

import "errors"

// Decision is deliberately limited to provider selection; it cannot sign or broadcast.
type Decision struct {
	Provider string
	Allowed  bool
}

func authorizeProvider(provider string, allowlist map[string]struct{}) (Decision, error) {
	if provider == "" {
		return Decision{}, errors.New("provider is required")
	}
	_, allowed := allowlist[provider]
	return Decision{Provider: provider, Allowed: allowed}, nil
}
