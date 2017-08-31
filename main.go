package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v2"
)

var (
	uaaURL               = flag.String("uaa.url", "", "Cloud Foundry UAA URL.")
	uaaClientID          = flag.String("uaa.client_id", "cf", "Cloud Foundry UAA Client ID.")
	uaaClientSecret      = flag.String("uaa.client_secret", "", "Cloud Foundry UAA Client Secret.")
	uaaUsername          = flag.String("uaa.username", "", "Cloud Foundry Username.")
	uaaPassword          = flag.String("uaa.password", "", "Cloud Foundry Password.")
	uaaSkipSSLValidation = flag.Bool("uaa.skip_ssl_verify", false, "Disable SSL Verify.")
)

type OIDCInfo struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimSupported                             []string `json:"claims_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ServiceDocumentation                       string   `json:"service_documentation"`
	UILocalesSupported                         []string `json:"ui_locales_supported"`
}

type AuthToken struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	JTI          string `json:"jti"`
}

type UserInfo struct {
	UserID            string `json:"user_id"`
	Sub               string `json:"sub"`
	UserName          string `json:"user_name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Email             string `json:"email"`
	PhoneNumber       string `json:"phone_number"`
	PreviousLogonTime int    `json:"previous_logon_time"`
	Name              string `json:"name"`
}

type Kubeconfig struct {
	AuthInfos []NamedAuthInfo `yaml:"users"`
}

type NamedAuthInfo struct {
	Name     string    `yaml:"name"`
	AuthInfo *AuthInfo `yaml:"user"`
}

type AuthInfo struct {
	AuthProvider *AuthProvider `yaml:"auth-provider"`
}

type AuthProvider struct {
	Name               string              `yaml:"name"`
	AuthProviderConfig *AuthProviderConfig `yaml:"config"`
}

type AuthProviderConfig struct {
	IdpIssuerURL string `yaml:"idp-issuer-url"`
	ClientID     string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
	IDToken      string `yaml:"id-token"`
	RefreshToken string `yaml:"refresh-token"`
}

func httpClient(skipSSLValidation bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipSSLValidation,
		},
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &http.Client{Transport: tr}
}

func getOIDCInfo(uaaURL string, skipSSLValidation bool) (*OIDCInfo, error) {
	oidcInfo := &OIDCInfo{}

	uri, err := url.Parse(uaaURL)
	if err != nil {
		return oidcInfo, fmt.Errorf("Error parsing UAA URL: %s", err)
	}

	request, err := http.NewRequest("GET", fmt.Sprintf("%s/.well-known/openid-configuration", uri), nil)
	if err != nil {
		return oidcInfo, fmt.Errorf("Error generating request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := httpClient(skipSSLValidation).Do(request)
	if err != nil {
		return oidcInfo, fmt.Errorf("Request error: %s", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return oidcInfo, fmt.Errorf("Received a %s status code", response.Status)
	}

	if err = json.NewDecoder(response.Body).Decode(oidcInfo); err != nil {
		return oidcInfo, fmt.Errorf("Error decoding response: %s", err)
	}

	return oidcInfo, nil
}

func getAuthToken(tokenEndpoint string, skipSSLValidation bool, clientID string, clientSecret string, username string, password string) (*AuthToken, error) {
	authToken := &AuthToken{}

	requestBody := url.Values{}
	requestBody.Set("username", username)
	requestBody.Set("password", password)
	requestBody.Set("grant_type", "password")
	requestBody.Set("response_type", "id_token")

	request, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(requestBody.Encode()))
	if err != nil {
		return authToken, fmt.Errorf("Error generating request: %s", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)

	response, err := httpClient(skipSSLValidation).Do(request)
	if err != nil {
		return authToken, fmt.Errorf("Request error: %s", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return authToken, fmt.Errorf("Received a %s status code", response.Status)
	}

	if err := json.NewDecoder(response.Body).Decode(authToken); err != nil {
		return authToken, fmt.Errorf("Error decoding response: %s", err)
	}

	return authToken, nil
}

func getUserInfo(userinfoEndpoint string, skipSSLValidation bool, tokenType string, accessToken string) (*UserInfo, error) {
	userInfo := &UserInfo{}

	request, err := http.NewRequest("GET", userinfoEndpoint, nil)
	if err != nil {
		return userInfo, fmt.Errorf("Error generating request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))

	response, err := httpClient(skipSSLValidation).Do(request)
	if err != nil {
		return userInfo, fmt.Errorf("Request error: %s", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return userInfo, fmt.Errorf("Received a %s status code", response.Status)
	}

	if err := json.NewDecoder(response.Body).Decode(userInfo); err != nil {
		return userInfo, fmt.Errorf("Error decoding response: %s", err)
	}

	return userInfo, nil
}

func generateUserKubeconfig(email string, issuer string, clientID string, clientSecret string, idToken string, refreshToken string) ([]byte, error) {
	kubeconfig := &Kubeconfig{
		AuthInfos: []NamedAuthInfo{
			NamedAuthInfo{
				Name: email,
				AuthInfo: &AuthInfo{
					AuthProvider: &AuthProvider{
						Name: "oidc",
						AuthProviderConfig: &AuthProviderConfig{
							IdpIssuerURL: issuer,
							ClientID:     clientID,
							ClientSecret: clientSecret,
							IDToken:      idToken,
							RefreshToken: refreshToken,
						},
					},
				},
			},
		},
	}

	output, err := yaml.Marshal(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling yaml: %s", err)
	}

	return output, nil
}

func main() {
	flag.Parse()

	if len(*uaaURL) == 0 {
		fmt.Print("uaa.url parameter is required")
		os.Exit(1)
	}

	if len(*uaaUsername) == 0 {
		fmt.Print("uaa.username parameter is required")
		os.Exit(1)
	}

	if len(*uaaPassword) == 0 {
		fmt.Print("uaa.password parameter is required")
		os.Exit(1)
	}

	oidcInfo, err := getOIDCInfo(*uaaURL, *uaaSkipSSLValidation)
	if err != nil {
		fmt.Printf("Error getting OIDC info: %s\n", err)
		os.Exit(1)
	}

	authToken, err := getAuthToken(oidcInfo.TokenEndpoint, *uaaSkipSSLValidation, *uaaClientID, *uaaClientSecret, *uaaUsername, *uaaPassword)
	if err != nil {
		fmt.Printf("Error getting auth code: %s\n", err)
		os.Exit(1)
	}

	userInfo, err := getUserInfo(oidcInfo.UserinfoEndpoint, *uaaSkipSSLValidation, authToken.TokenType, authToken.AccessToken)
	if err != nil {
		fmt.Printf("Error getting user info: %s\n", err)
		os.Exit(1)
	}

	userKubeconfig, err := generateUserKubeconfig(userInfo.Email, oidcInfo.Issuer, *uaaClientID, *uaaClientSecret, authToken.IDToken, authToken.RefreshToken)
	if err != nil {
		fmt.Printf("Error generating user kubeconfig: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("# Add the following to your ~/.kube/config")
	fmt.Println(string(userKubeconfig))
	os.Exit(0)
}
