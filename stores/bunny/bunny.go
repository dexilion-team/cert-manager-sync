package bunny

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// apiBaseURL is the Bunny.net core API endpoint. Defined as a var so tests can
// point the store at an httptest server.
var apiBaseURL = "https://api.bunny.net"

var httpClient = &http.Client{Timeout: 30 * time.Second}

// BunnyStore attaches certificates to custom hostnames of a Bunny.net Pull
// Zone. Bunny keys certificates by hostname rather than by a remote id, so
// there is nothing to write back to the secret after a sync: re-adding a
// certificate to a hostname replaces the one already there.
type BunnyStore struct {
	SecretName      string
	SecretNamespace string
	ApiKey          string
	PullZoneId      string
	Hostnames       []string
}

func (s *BunnyStore) GetApiKey(ctx context.Context) error {
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return fmt.Errorf("failed to get Bunny credentials secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
	}
	if sc.Data["api_key"] == nil {
		return fmt.Errorf("api_key not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	s.ApiKey = string(sc.Data["api_key"])
	return nil
}

func (s *BunnyStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["pull-zone-id"] != "" {
		s.PullZoneId = c.Config["pull-zone-id"]
	}
	if c.Config["hostname"] != "" {
		// a single certificate (e.g. a wildcard or SAN cert) may serve several
		// hostnames of the same pull zone
		s.Hostnames = nil
		for _, h := range strings.Split(c.Config["hostname"], ",") {
			if h = strings.TrimSpace(h); h != "" {
				s.Hostnames = append(s.Hostnames, h)
			}
		}
	}
	// if secret name is in the format of "namespace/secretname" then parse it
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	return nil
}

// validate checks the config shared by Sync and Delete. The pull zone id is
// interpolated into the request path, so it must be a plain integer.
func (s *BunnyStore) validate() error {
	if s.SecretName == "" {
		return fmt.Errorf("bunny secret-name not set")
	}
	if s.PullZoneId == "" {
		return fmt.Errorf("bunny pull-zone-id not set")
	}
	if _, err := strconv.ParseInt(s.PullZoneId, 10, 64); err != nil {
		return fmt.Errorf("bunny pull-zone-id %q is not a valid integer", s.PullZoneId)
	}
	if len(s.Hostnames) == 0 {
		return fmt.Errorf("bunny hostname not set")
	}
	return nil
}

// apiError is the ApiErrorData body Bunny returns on 400 responses.
type apiError struct {
	ErrorKey string `json:"ErrorKey"`
	Field    string `json:"Field"`
	Message  string `json:"Message"`
}

type addCertificateRequest struct {
	Hostname       string `json:"Hostname"`
	Certificate    string `json:"Certificate"`
	CertificateKey string `json:"CertificateKey"`
}

type removeCertificateRequest struct {
	Hostname string `json:"Hostname"`
}

// do sends a JSON request to the Bunny API and returns the response status
// code. Any non-2xx status is returned as an error alongside the code.
func (s *BunnyStore) do(ctx context.Context, method, path string, body interface{}) (int, error) {
	jd, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal Bunny request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBaseURL+path, bytes.NewReader(jd))
	if err != nil {
		return 0, fmt.Errorf("failed to create Bunny API request: %w", err)
	}
	req.Header.Set("AccessKey", s.ApiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return res.StatusCode, nil
	}
	bd, _ := io.ReadAll(res.Body)
	ae := &apiError{}
	if json.Unmarshal(bd, ae) == nil && ae.Message != "" {
		return res.StatusCode, fmt.Errorf("status %d: %s (%s)", res.StatusCode, ae.Message, ae.ErrorKey)
	}
	return res.StatusCode, fmt.Errorf("status %d: %s", res.StatusCode, strings.TrimSpace(string(bd)))
}

func (s *BunnyStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	if s.SecretNamespace == "" {
		s.SecretNamespace = c.Namespace
	}
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "bunny",
		"pullZoneId":      s.PullZoneId,
		"hostnames":       s.Hostnames,
		"secretName":      s.SecretName,
		"secretNamespace": s.SecretNamespace,
	})
	l.Debugf("Update")
	if err := s.validate(); err != nil {
		return nil, err
	}
	ctx := context.Background()
	if err := s.GetApiKey(ctx); err != nil {
		l.WithError(err).Errorf("GetApiKey error")
		return nil, fmt.Errorf("failed to get Bunny API key from secret %s/%s: %w", s.SecretNamespace, s.SecretName, err)
	}
	bCert := base64.StdEncoding.EncodeToString(c.FullChain())
	bKey := base64.StdEncoding.EncodeToString(c.Key)
	for _, h := range s.Hostnames {
		if _, err := s.do(ctx, http.MethodPost, "/pullzone/"+s.PullZoneId+"/addCertificate", &addCertificateRequest{
			Hostname:       h,
			Certificate:    bCert,
			CertificateKey: bKey,
		}); err != nil {
			l.WithError(err).WithField("hostname", h).Errorf("addCertificate error")
			return nil, fmt.Errorf("failed to add certificate to Bunny pull zone %s hostname %s: %w", s.PullZoneId, h, err)
		}
		l.WithField("hostname", h).Debug("certificate added")
	}
	l.Info("certificate synced")
	return nil, nil
}

// Delete removes the certificate from each configured hostname of the pull
// zone. A 404 means the pull zone itself is gone, which is treated as success
// so the operation is idempotent.
func (s *BunnyStore) Delete(ctx context.Context) error {
	l := log.WithFields(log.Fields{
		"action":     "bunny.Delete",
		"pullZoneId": s.PullZoneId,
		"hostnames":  s.Hostnames,
	})
	if err := s.validate(); err != nil {
		return fmt.Errorf("cannot delete Bunny certificate: %w", err)
	}
	if err := s.GetApiKey(ctx); err != nil {
		return fmt.Errorf("bunny credentials lookup failed: %w", err)
	}
	for _, h := range s.Hostnames {
		code, err := s.do(ctx, http.MethodDelete, "/pullzone/"+s.PullZoneId+"/removeCertificate", &removeCertificateRequest{
			Hostname: h,
		})
		if err != nil {
			if code == http.StatusNotFound {
				l.Debug("bunny pull zone already absent; treating delete as success")
				return nil
			}
			return fmt.Errorf("remove Bunny certificate from pull zone %s hostname %s: %w", s.PullZoneId, h, err)
		}
		l.WithField("hostname", h).Debug("certificate removed")
	}
	l.Info("certificate deleted from bunny")
	return nil
}
