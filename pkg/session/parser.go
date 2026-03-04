package session

import (
	"fmt"
	"strings"
	"strconv"
)

// ParseTargetString parses a string in the format [domain/]user[:password]@target[:port]
func ParseTargetString(input string) (Target, Credentials, error) {
	var target Target
	var creds Credentials

	// Split on the LAST @ to handle passwords containing @
	lastAt := strings.LastIndex(input, "@")
	if lastAt == -1 {
		return target, creds, fmt.Errorf("invalid format: missing '@'")
	}

	authPart := input[:lastAt]
	targetPart := input[lastAt+1:]

	// Handle target host and port
	if strings.Contains(targetPart, ":") {
		tParts := strings.SplitN(targetPart, ":", 2)
		target.Host = tParts[0]
		p, err := strconv.Atoi(tParts[1])
		if err == nil {
			target.Port = p
		}
	} else {
		target.Host = targetPart
		target.Port = 0 // Tool will set default
	}

	// Handle domain/user and password
	authSplit := strings.SplitN(authPart, ":", 2)
	userPart := authSplit[0]
	if len(authSplit) == 2 {
		creds.Password = authSplit[1]
	}

	if strings.Contains(userPart, "/") {
		userSplit := strings.SplitN(userPart, "/", 2)
		creds.Domain = userSplit[0]
		creds.Username = userSplit[1]
	} else {
		creds.Username = userPart
	}

	return target, creds, nil
}