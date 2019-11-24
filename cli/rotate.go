package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RotateCommandInput struct {
	ProfileName string
	Keyring     keyring.Keyring
	Config      vault.Config
}

func ConfigureRotateCommand(app *kingpin.Application) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotates credentials")

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("mfa-serial", "The identification number of the MFA device to use").
		StringVar(&input.Config.MfaSerial)

	cmd.Flag("no-session", "Use stored credentials directly, no session created").
		Short('n').
		BoolVar(&input.Config.NoSession)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Config.MfaPromptMethod = GlobalFlags.PromptDriver
		input.Keyring = keyringImpl
		RotateCommand(app, input)
		return nil
	})
}

func RotateCommand(app *kingpin.Application, input RotateCommandInput) {
	err := configLoader.LoadFromProfile(input.ProfileName, &input.Config)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if input.Config.CredentialsName != input.Config.ProfileName {
		fmt.Printf("Using profile '%s' to rotate the credentials for profile '%s' (takes 10-20 seconds)\n", input.Config.ProfileName, input.Config.CredentialsName)
	} else {
		fmt.Printf("Rotating credentials for profile '%s' (takes 10-20 seconds)\n", input.Config.CredentialsName)
	}

	if err := vault.Rotate(input.Keyring, &input.Config); err != nil {
		app.Fatalf(err.Error())
		return
	}

	fmt.Printf("Done!\n")
}
