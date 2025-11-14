//go:build unit

package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
)

const secret = `{"Field1": "value1", "Field2": "value2", "Field3": "value3"}`

type mockSecretsManagerAPI interface {
	GetSecretValue(
		ctx context.Context,
		params *secretsmanager.GetSecretValueInput,
		opts ...func(*secretsmanager.Options),
	) (*secretsmanager.GetSecretValueOutput, error)

	PutSecretValue(
		ctx context.Context,
		params *secretsmanager.PutSecretValueInput,
		opts ...func(*secretsmanager.Options),
	) (*secretsmanager.PutSecretValueOutput, error)
}

type mockSecretsManager struct{}

func (m mockSecretsManager) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	resp := secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(secret),
	}
	return &resp, nil
}

func (m mockSecretsManager) PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	return nil, nil
}

func GetTestSecretClient(t *testing.T) SecretClient {
	test_svc := mockSecretsManager{}
	return SecretClient{Svc: test_svc}
}

func TestGetSecret(t *testing.T) {
	test_client := GetTestSecretClient(t)
	test_secret_val, _ := test_client.GetSecret("blob")
	assert.Equal(t, secret, test_secret_val)
}

func TestPutSecret(t *testing.T) {
	test_client := GetTestSecretClient(t)
	err := test_client.PutSecret("secret-key", "blob")
	assert.Equal(t, err, nil)
}

func TestGetSecretData(t *testing.T) {
	test_client := GetTestSecretClient(t)
	test_secret_data, _ := test_client.GetSecret("blob")
	assert.Equal(t, secret, test_secret_data)
}
