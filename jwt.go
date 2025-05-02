package jwtHelper

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"strconv"
	"strings"
	"time"

	errorhelper "github.com/gigatar/error-helper"
	"github.com/golang-jwt/jwt/v4"
)

type claim struct {
	Email string   `json:"email"`
	ID    string   `json:"id"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

func CreateJWT(email, id, issuer string, roles []string) (tokenString string, err error) {

	password := os.Getenv("JWT_PASSWORD")
	ttl, err := strconv.Atoi(os.Getenv("JWT_TTL"))
	if err != nil {
		if !errors.Is(err, strconv.ErrSyntax) {
			return "", errorhelper.ErrUnknown
		}
		ttl = 5
	}

	if password == "" {
		return "", errorhelper.ErrUnknown
	}

	expiration := time.Now().Add(time.Minute * time.Duration(ttl))
	claims := &claim{
		Email: email,
		Roles: roles,
		ID:    id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			Issuer:    issuer,
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	if tokenString, err = token.SignedString([]byte(password)); err != nil {
		return "", err
	}

	return
}

func ValidateJWT(requiredClaims []string, errorEncoder errorhelper.Encoder) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			password := os.Getenv("JWT_PASSWORD")
			if password == "" {
				log.Println("ValidateJWT Error")
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else {

				if len(r.Header.Get("Authorization")) < 8 {
					errorEncoder.Encode(r.Context(), errorhelper.ErrUnauthorized, w)
					return
				}
				tokenString := strings.Split(r.Header.Get("Authorization"), "Bearer ")[1]
				if tokenString == "" {
					errorEncoder.Encode(r.Context(), errorhelper.ErrUnauthorized, w)
					return
				}

				var claims claim
				token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
					// Validate algo
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return []byte(password), nil
				})

				if err != nil {
					errorEncoder.Encode(r.Context(), errorhelper.ErrUnauthorized, w)
					return
				}

				// Validate required claims
				if !hasRequiredClaims(claims.Roles, requiredClaims) {
					errorEncoder.Encode(r.Context(), errorhelper.ErrForbidden, w)
					return
				}

				if claims, ok := token.Claims.(*claim); ok && token.Valid {
					// Add the audience into the HTTP request so that we can grab it later.
					// This allows us to pass it into the service layer via context or do other fun stuff.
					r.Header.Add("email", claims.Email)
					r.Header.Add("user-id", claims.ID)
					r.Header.Add("roles", strings.Join(claims.Roles, ":"))
					next.ServeHTTP(w, r)
				} else {
					errorEncoder.Encode(r.Context(), errorhelper.ErrUnauthorized, w)
					return
				}
			}
		})
	}
}

func hasRequiredClaims(userRoles []string, requiredClaims []string) bool {
	m := make(map[string]struct{}, len(userRoles))
	for _, r := range userRoles {
		m[r] = struct{}{}
	}

	for _, c := range requiredClaims {
		if _, ok := m[c]; !ok {
			return false
		}
	}

	return true
}
