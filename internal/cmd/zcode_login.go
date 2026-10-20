package cmd

import (
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	log "github.com/sirupsen/logrus"
)

func DoZCodeLogin(cfg *config.Config, options *LoginOptions, family, plan string) {
	if options == nil {
		options = &LoginOptions{}
	}
	_, path, err := newAuthManager().Login(context.Background(), "zcode", cfg, &sdkAuth.LoginOptions{
		NoBrowser: options.NoBrowser, Metadata: map[string]string{"family": family, "plan": plan},
	})
	if err != nil {
		log.WithError(err).Error("ZCode login failed")
		return
	}
	fmt.Printf("ZCode authentication saved to %s. Configure the account's models before serving requests.\n", path)
}
