package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type client struct {
	endpoint, keyID, secret, audience string
	http                              *http.Client
}

func main() { plugin.Serve(&plugin.ServeOpts{ProviderFunc: Provider}) }
func Provider() *schema.Provider {
	p := &schema.Provider{Schema: map[string]*schema.Schema{}, ResourcesMap: map[string]*schema.Resource{"aaztce_workflow": workflow()}}
	for _, k := range []string{"endpoint", "key_id", "key_file", "ca_file", "cert_file", "cert_key_file"} {
		p.Schema[k] = &schema.Schema{Type: schema.TypeString, Required: true}
	}
	p.Schema["audience"] = &schema.Schema{Type: schema.TypeString, Optional: true, Default: "Domain-X"}
	p.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		c, e := newClient(d)
		if e != nil {
			return nil, diag.FromErr(e)
		}
		return c, nil
	}
	return p
}
func newClient(d *schema.ResourceData) (*client, error) {
	endpoint := strings.TrimRight(d.Get("endpoint").(string), "/")
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("endpoint must be an HTTPS origin")
	}
	key, e := os.ReadFile(d.Get("key_file").(string))
	if e != nil {
		return nil, fmt.Errorf("operator key unavailable")
	}
	secret := strings.TrimSpace(string(key))
	if len(secret) < 32 {
		return nil, fmt.Errorf("operator key too short")
	}
	ca, e := os.ReadFile(d.Get("ca_file").(string))
	if e != nil {
		return nil, fmt.Errorf("CA unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid CA")
	}
	cert, e := tls.LoadX509KeyPair(d.Get("cert_file").(string), d.Get("cert_key_file").(string))
	if e != nil {
		return nil, fmt.Errorf("client certificate/key unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}}
	return &client{endpoint: endpoint, keyID: d.Get("key_id").(string), secret: secret, audience: d.Get("audience").(string), http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *client) call(ctx context.Context, method, name string, body interface{}) (map[string]interface{}, int, error) {
	if !regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`).MatchString(name) {
		return nil, 0, fmt.Errorf("invalid workflow name")
	}
	target := "/v1/workflows/" + name
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, 0, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.endpoint+target, strings.NewReader(string(raw)))
	if e != nil {
		return nil, 0, e
	}
	nonce := make([]byte, 24)
	if _, e = rand.Read(nonce); e != nil {
		return nil, 0, e
	}
	n := hex.EncodeToString(nonce)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	hash := sha256.Sum256(raw)
	message := strings.Join([]string{method, target, c.audience, ts, n, hex.EncodeToString(hash[:])}, "\n")
	mac := hmac.New(sha256.New, []byte(c.secret))
	mac.Write([]byte(message))
	for k, v := range map[string]string{"Content-Type": "application/json", "X-AA-Key-ID": c.keyID, "X-AA-Audience": c.audience, "X-AA-Timestamp": ts, "X-AA-Nonce": n, "X-AA-Signature": hex.EncodeToString(mac.Sum(nil))} {
		req.Header.Set(k, v)
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, 0, fmt.Errorf("workflow transport failed: %w", e)
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(data) > 65536 {
		return nil, resp.StatusCode, fmt.Errorf("invalid response size")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		return nil, resp.StatusCode, fmt.Errorf("workflow API HTTP %d; refresh state for revision conflicts", resp.StatusCode)
	}
	result := map[string]interface{}{}
	if e = json.Unmarshal(data, &result); e != nil {
		return nil, resp.StatusCode, fmt.Errorf("invalid JSON response")
	}
	return result, resp.StatusCode, nil
}
func workflow() *schema.Resource {
	fields := map[string]*schema.Schema{"name": {Type: schema.TypeString, Required: true, ForceNew: true}, "purpose": {Type: schema.TypeString, Required: true}, "revision": {Type: schema.TypeInt, Computed: true}}
	for _, k := range []string{"agents", "resources", "destinations"} {
		fields[k] = &schema.Schema{Type: schema.TypeSet, Required: true, MinItems: 1, MaxItems: 32, Elem: &schema.Schema{Type: schema.TypeString}}
	}
	r := &schema.Resource{Schema: fields, Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext}}
	r.ReadContext = readWorkflow
	r.CreateContext = saveWorkflow
	r.UpdateContext = saveWorkflow
	r.DeleteContext = func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		_, _, e := meta.(*client).call(ctx, "DELETE", d.Id(), map[string]interface{}{"expected_revision": d.Get("revision")})
		if e != nil {
			return diag.FromErr(e)
		}
		d.SetId("")
		return nil
	}
	return r
}
func readWorkflow(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	result, status, e := meta.(*client).call(ctx, "GET", d.Id(), nil)
	if e != nil {
		return diag.FromErr(e)
	}
	if status == 404 {
		d.SetId("")
		return nil
	}
	if e = d.Set("name", d.Id()); e != nil {
		return diag.FromErr(e)
	}
	for _, k := range []string{"agents", "resources", "destinations", "purpose", "revision"} {
		if e = d.Set(k, result[k]); e != nil {
			return diag.FromErr(e)
		}
	}
	return nil
}
func saveWorkflow(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	body := map[string]interface{}{"purpose": d.Get("purpose"), "expected_revision": d.Get("revision")}
	if d.Id() == "" {
		body["expected_revision"] = 0
	}
	for _, k := range []string{"agents", "resources", "destinations"} {
		body[k] = d.Get(k).(*schema.Set).List()
	}
	name := d.Get("name").(string)
	result, _, e := meta.(*client).call(ctx, "PUT", name, body)
	if e != nil {
		return diag.FromErr(e)
	}
	d.SetId(name)
	if e = d.Set("revision", result["revision"]); e != nil {
		return diag.FromErr(e)
	}
	return nil
}
