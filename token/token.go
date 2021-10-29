package token

import (
	"errors"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v4"
)

func getKey(t *jwt.Token, keys []map[string]interface{}) (interface{}, error) {
	alg, _ := t.Header["alg"].(string)
	if alg != "HS256" && alg != "HS384" && alg != "HS512" {
		return nil, errors.New("unknown signature algorithm")
	}
	kid, _ := t.Header["kid"].(string)
	for _, k := range keys {
		kid2, _ := k["kid"].(string)
		alg2, _ := k["alg"].(string)
		if (kid == "" || kid == kid2) && alg == alg2 {
			k, ok := k["k"].(string)
			if !ok {
				return nil, errors.New("bad type for 'k' field")
			}
			kk, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				return nil, err
			}
			return kk, nil
		}
	}
	return nil, errors.New("key not found")
}

func Valid(username, group, token string, keys []map[string]interface{}) (map[string]interface{}, error) {
	tok, err := jwt.Parse(token, func (t *jwt.Token) (interface{}, error) {
		return getKey(t, keys)
	})
	if err != nil {
		return nil, err
	}
	claims := tok.Claims.(jwt.MapClaims)

	sub, ok := claims["sub"].(string)
	if !ok || sub != username {
		return nil, errors.New("invalid 'sub' field")
	}
	aud, ok := claims["aud"]
	audOk := false
	if ok {
		switch aud := aud.(type) {
		case string:
			audOk = aud == group
		case []string:
			for _, a := range aud {
				if a == group {
					audOk = true
					break
				}
			}
		}
	}
	if !audOk {
		return nil, errors.New("invalid 'aud' field")
	}
	perms, ok := claims["permissions"].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid 'permissions' field")
	}
	return perms, nil
}

