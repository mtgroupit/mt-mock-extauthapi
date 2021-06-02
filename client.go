// Package extauthapi implementaton for debugging and testing.
package extauthapi

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
)

// Client for extauthapi.
type Client struct {
}

// NewClient creates and return new client for extauthapi.
func NewClient(endpoint string, tlsConfig *tls.Config, autoRetryCSRF bool) (*Client, error) {
	return &Client{}, nil
}

// Authz describes user roles/permissions.
type Authz struct {
	User    bool
	Admin   bool
	Manager bool
}

// Profile describes user profile returned by /get-user-profile.
type Profile struct {
	ID               ID
	Authn            bool
	Authz            Authz
	IsolatedEntityID ID
	DepartmentID     int
	DepartmentName   string
}

func newProfile(userID, isolatedEntityID ID, authn, user, manager, admin bool) *Profile {
	return &Profile{
		ID:    userID,
		Authn: authn,
		Authz: Authz{
			User:    user,
			Manager: manager,
			Admin:   admin,
		},
		IsolatedEntityID: isolatedEntityID,
	}
}

// GetUserProfile gets a cookie with the userID and isolatedEntityID separated by a dot(.) and returns a profile with the values from the cookie.
// Authn is always true.
func (c *Client) GetUserProfile(ctx context.Context, rawCookies string) (*Profile, error) {
	return parseCookie(parseCookieRaw(rawCookies)), nil
}

func parseCookieRaw(rawCookies string) string {
	header := http.Header{}
	header.Add("Cookie", rawCookies)
	request := http.Request{Header: header}

	cookieKey, err := request.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}

	return cookieKey.Value
}

func parseCookie(cookie string) *Profile {
	idStrs := strings.SplitN(cookie, ".", 3)

	var userID, isoEntityID ID
	var authn, user, manager, admin bool
	var err error
	if len(idStrs) > 0 {
		userID, err = ParseID(idStrs[0])
		if err != nil {
			userID = NewID()
		}
		if len(idStrs) > 1 {
			isoEntityID, err = ParseID(idStrs[1])
			if err != nil {
				isoEntityID = NewID()
			}
			if len(idStrs) > 2 {
				switch idStrs[2] {
				case "manager":
					manager = true
				case "admin":
					admin = true
				}
			}
		} else {
			isoEntityID = NewID()
		}
		authn = true
		user = true
	}

	return newProfile(userID, isoEntityID, authn, user, manager, admin)
}

// Validate return nil if token is valid
func (c *Client) Validate(ctx context.Context, token, remoteIP string) error {
	if len(token) < 1 || len(token) > 1000 {
		return errors.New("Token defective")
	}
	return nil
}
