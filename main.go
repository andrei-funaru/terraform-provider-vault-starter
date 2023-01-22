package main

import (
	"context"
	"flag"
	"log"

	"github.com/andrei-funaru/terraform-provider-vault-starter/internal/provider"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

var (
	version string = "dev"
)

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := &plugin.ServeOpts{ProviderFunc: provider.New(version)}

	if debugMode {
		err := plugin.Debug(context.Background(), "registry.terraform.io/andrei-funaru/vault-starter", opts)
		if err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	plugin.Serve(opts)
}
