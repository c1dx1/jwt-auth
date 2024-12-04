package models

type AccessRequest struct {
	GUID string `form:"guid"`
	IP   string
	Iat  int64
}

type RefreshRequest struct {
	AccessToken  string
	RefreshToken string
	GUID         string
	IP           string
	Iat          int64
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
