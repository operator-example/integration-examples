package auth

import (
	"encoding/base64"
	"regexp"
)

var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

func decodeBase64(value string) ([]byte, bool) {
	if len(value)%4 != 0 || !base64Pattern.MatchString(value) {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return decoded, err == nil
}
