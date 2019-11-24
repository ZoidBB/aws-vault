package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/iam"
)

func Rotate(keyring keyring.Keyring, config *Config) error {

	masterCredsProvider := NewMasterCredentialsProvider(keyring, config.CredentialsName)

	// Get the existing credentials
	oldMasterCreds, err := credentials.NewCredentials(masterCredsProvider).Get()
	if err != nil {
		return err
	}
	log.Printf("Found old access key ****************%s", oldMasterCreds.AccessKeyID[len(oldMasterCreds.AccessKeyID)-4:])

	// create a session to rotate the credentials
	workingCredsProvider, err := NewTempCredentialsProvider(keyring, config)
	if err != nil {
		return err
	}
	workingCreds := credentials.NewCredentials(workingCredsProvider)
	workingSession := newSession(workingCreds, config.Region)

	var iamUserName *string

	// A username is needed for some IAM calls if the credentials have assumed a role
	if config.RoleARN != "" {
		userName, err := GetUsernameFromSession(workingSession)
		if err != nil {
			return err
		}
		log.Printf("Found IAM username '%s'", userName)

		iamUserName = aws.String(userName)
	}

	log.Println("Using old credentials to create a new access key")

	// Create a new access key
	createOutput, err := iam.New(workingSession).CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: iamUserName,
	})
	if err != nil {
		return err
	}

	akid := *createOutput.AccessKey.AccessKeyId
	log.Printf("Created new access key ****************%s", akid[len(akid)-4:])

	newMasterCreds := credentials.Value{
		AccessKeyID:     *createOutput.AccessKey.AccessKeyId,
		SecretAccessKey: *createOutput.AccessKey.SecretAccessKey,
	}

	err = masterCredsProvider.Store(newMasterCreds)
	if err != nil {
		return fmt.Errorf("Error storing new access key %v: %v", newMasterCreds.AccessKeyID, err)
	}

	// Delete old sessions
	sessions := NewKeyringSessions(keyring)
	if n, _ := sessions.Delete(config.CredentialsName); n > 0 {
		log.Printf("Deleted %d existing sessions.", n)
	}

	// expire the cached credentials
	workingCredsProvider.ForceRefresh()
	workingCreds.Expire()

	log.Println("Using new credentials to delete the old new access key")
	log.Println("Waiting for new IAM credentials to propagate (takes up to 10 seconds)")

	// Use new credentials to delete old access key
	err = retry(time.Second*30, time.Second*5, func() error {
		_, err = iam.New(workingSession).DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: aws.String(oldMasterCreds.AccessKeyID),
			UserName:    iamUserName,
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("Can't delete old access key %v: %v", oldMasterCreds.AccessKeyID, err)
	}

	log.Printf("Rotated credentials '%q' in vault", config.CredentialsName)
	return nil
}

func retry(maxTime time.Duration, sleep time.Duration, f func() error) (err error) {
	t0 := time.Now()
	i := 0
	for {
		i++

		err = f()
		if err == nil {
			return
		}

		elapsed := time.Now().Sub(t0)
		if elapsed > maxTime {
			return fmt.Errorf("After %d attempts, last error: %s", i, err)
		}

		time.Sleep(sleep)
		log.Println("Retrying after error:", err)
	}
}
