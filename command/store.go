package command

import (
	"flag"
	"fmt"
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

type StoreCommand struct {
	Ui      cli.Ui
	Keyring keyring.Keyring
}

func (c *StoreCommand) Run(args []string) int {
	config, err := parseFlags(args, func(f *flag.FlagSet) {
		f.Usage = func() { c.Ui.Output(c.Help()) }
	})
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	accessKeyId, err := c.Ui.Ask("Enter Access Key ID: ")
	if err != nil {
		c.Ui.Error(err.Error())
		return 2
	}

	secretKey, err := c.Ui.AskSecret("Enter Secret Access Key: ")
	if err != nil {
		c.Ui.Error(err.Error())
		return 2
	}

	creds := vault.Credentials{accessKeyId, secretKey}

	if err = keyring.Marshal(c.Keyring, vault.ServiceName, config.Profile, &creds); err != nil {
		c.Ui.Error(err.Error())
		return 3
	}

	c.Ui.Info(fmt.Sprintf("\nAdded credentials to profile %q in vault", config.Profile))
	return 0
}

func (c *StoreCommand) Help() string {
	helpText := `
Usage: aws-vault store [--profile=default]
  Stores a Access Key Id and Secret Access Key to the vault via interactive prompts.
`
	return strings.TrimSpace(helpText)
}

func (c *StoreCommand) Synopsis() string {
	return "Store credentials to the vault via interactive prompts"
}