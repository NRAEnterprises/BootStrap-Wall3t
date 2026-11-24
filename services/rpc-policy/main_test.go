package main

import "testing"

func TestAuthorizeProvider(t *testing.T) {
	decision, err := authorizeProvider("https://rpc.example", map[string]struct{}{"https://rpc.example": {}})
	if err != nil || !decision.Allowed {
		t.Fatalf("expected allowlisted provider, got %#v, %v", decision, err)
	}
	decision, err = authorizeProvider("https://evil.example", map[string]struct{}{"https://rpc.example": {}})
	if err != nil || decision.Allowed {
		t.Fatalf("expected rejected provider, got %#v, %v", decision, err)
	}
}
