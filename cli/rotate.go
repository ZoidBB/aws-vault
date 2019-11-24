package cli

import (
	"fmt"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type RotateCommandInput struct {
	CredentialsName string
	ProfileName     string
	Keyring         keyring.Keyring
	Config          vault.Config
}

func ConfigureRotateCommand(app *kingpin.Application) {
	input := RotateCommandInput{}

	cmd := app.Command("rotate", "Rotates credentials")

	cmd.Arg("profile", "Name of the profile with credentials to rotate").
		Required().
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.CredentialsName)

	cmd.Flag("use-profile", "Name of the profile to use while rotating the credentials.").
		HintAction(awsConfigFile.ProfileNames).
		StringVar(&input.ProfileName)

	cmd.Flag("mfa-token", "The mfa token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("mfa-serial", "The identification number of the MFA device to use").
		StringVar(&input.Config.MfaSerial)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Config.MfaPromptMethod = GlobalFlags.PromptDriver
		input.Keyring = keyringImpl
		RotateCommand(app, input)
		return nil
	})
}

func RotateCommand(app *kingpin.Application, input RotateCommandInput) {
	configProfileName := input.CredentialsName
	if input.ProfileName != "" {
		configProfileName = input.ProfileName
	}

	err := configLoader.LoadFromProfile(configProfileName, &input.Config)
	if err != nil {
		app.Fatalf("%v", err)
		return
	}

	if input.ProfileName == "" {
		if input.Config.ProfileName != input.Config.CredentialsName {
			app.Fatalf("Credentials for profile '%s' are sourced from '%s'. Try 'aws-vault rotate %s' instead",
				input.Config.ProfileName, input.Config.CredentialsName, input.Config.CredentialsName)
			return
		}
		input.Config.NoSession = true
		input.Config.RoleARN = ""

		fmt.Printf("Rotating credentials '%s' (takes 10-20 seconds)\n", input.Config.CredentialsName)
	} else {
		if input.CredentialsName != input.Config.CredentialsName {
			app.Fatalf("Credentials for profile '%s' are sourced from '%s'. Try 'aws-vault rotate %s' instead",
				input.ProfileName, input.Config.CredentialsName, input.Config.CredentialsName)
			return
		}

		fmt.Printf("Rotating credentials '%s' using profile '%s' (takes 10-20 seconds)\n", input.Config.CredentialsName, input.Config.ProfileName)
	}

	if err := vault.Rotate(input.Keyring, &input.Config); err != nil {
		app.Fatalf(err.Error())
		return
	}

	fmt.Printf("Done!\n")
}
