package main

import (
	"context"
	"encoding/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"os"
	"testing"
)

func TestProviderSchema(t *testing.T) {
	if e := Provider().InternalValidate(); e != nil {
		t.Fatal(e)
	}
}

func TestGatewayLifecycle(t *testing.T) {
	path := os.Getenv("AA_ZTCE_PROVIDER_CONFIG")
	if path == "" {
		t.Skip("live local gateway config not supplied")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	config := map[string]interface{}{}
	if e = json.Unmarshal(raw, &config); e != nil {
		t.Fatal(e)
	}
	p := Provider()
	d := schema.TestResourceDataRaw(t, p.Schema, config)
	c, e := newClient(d)
	if e != nil {
		t.Fatal(e)
	}
	r := workflow()
	data := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{"name": "go_provider_test", "agents": []interface{}{"A"}, "resources": []interface{}{"inventory"}, "destinations": []interface{}{"internal"}, "purpose": "go-created"})
	ctx := context.Background()
	if result := saveWorkflow(ctx, data, c); result.HasError() {
		t.Fatal(result)
	}
	if data.Id() != "go_provider_test" || data.Get("revision").(int) != 1 {
		t.Fatal("create did not set state")
	}
	if result := readWorkflow(ctx, data, c); result.HasError() {
		t.Fatal(result)
	}
	if e = data.Set("purpose", "go-updated"); e != nil {
		t.Fatal(e)
	}
	if result := saveWorkflow(ctx, data, c); result.HasError() {
		t.Fatal(result)
	}
	if data.Get("revision").(int) != 2 {
		t.Fatal("update revision not advanced")
	}
	if e = data.Set("revision", 1); e != nil {
		t.Fatal(e)
	}
	if result := saveWorkflow(ctx, data, c); !result.HasError() {
		t.Fatal("stale update was accepted")
	}
	if result := readWorkflow(ctx, data, c); result.HasError() {
		t.Fatal(result)
	}
	if result := r.DeleteContext(ctx, data, c); result.HasError() {
		t.Fatal(result)
	}
	if data.Id() != "" {
		t.Fatal("destroy did not clear state")
	}
	data.SetId("go_provider_test")
	if result := readWorkflow(ctx, data, c); result.HasError() {
		t.Fatal(result)
	}
	if data.Id() != "" {
		t.Fatal("missing remote workflow did not clear state")
	}
}
