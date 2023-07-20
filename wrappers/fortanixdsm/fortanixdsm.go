package fortanixdsm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/fortanix/sdkms-client-go/sdkms"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	EnvFortanixDsmKeyId = "FORTANIX_KEY_ID"
)

const (
	FortanixDsmEncrypt = iota
	FortanixDsmEnvelopeEncrypt
)

type Wrapper struct {
	apiKey   string
	endpoint string
	keyName  string
	client   *sdkmsClient

	currentKeyId *atomic.Value

	logger hclog.Logger
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new wrapper with the given options
func NewWrapper() *Wrapper {
	v := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	v.currentKeyId.Store("")
	return v
}

// Type returns the wrapping type for this particular Wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeFortanixDsm, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

func (v *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	v.logger = opts.withLogger

	switch {
	case os.Getenv("FORTANIX_SEAL_API_KEY") != "" && !opts.withDisallowEnvVars:
		v.apiKey = os.Getenv("FORTANIX_SEAL_API_KEY")
	case opts.withApikey != "":
		v.apiKey = opts.withApikey
	}

	switch {
	case os.Getenv("FORTANIX_SEAL_ENDPOINT") != "" && !opts.withDisallowEnvVars:
		v.endpoint = os.Getenv("FORTANIX_SEAL_ENDPOINT")
	case opts.withEndpoint != "":
		v.endpoint = opts.withEndpoint
	}

	switch {
	case os.Getenv("FORTANIX_SEAL_KEYNAME") != "" && !opts.withDisallowEnvVars:
		v.keyName = os.Getenv("FORTANIX_SEAL_KEYNAME")
	case opts.withKeyName != "":
		v.keyName = opts.withKeyName
	}

	if v.client == nil {
		client, err := v.getDsmClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing Fortaix DSM client: %w", err)
		}

		var sobjDescriptor sdkms.SobjectDescriptor
		// Test the client connection using provided key ID
		sobjDescriptor = sdkms.SobjectDescriptor{
			Name: &v.keyName,
		}

		_, err = client.GetSobject(context.Background(), nil, sobjDescriptor)
		if err != nil {
			return nil, fmt.Errorf("error fetching FortanixDSM wrapper key information: %w", err)
		}
		v.client = client
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["endpoint"] = v.endpoint
	wrapConfig.Metadata["keyName"] = v.keyName

	return wrapConfig, nil
}

func (v *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}
	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)

	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	if v.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	contxt := context.Background()
	sobjDescriptor := sdkms.SobjectDescriptor{
		Name: &v.keyName,
	}
	encryptReq := sdkms.EncryptRequest{
		Plain: env.Key,
		Alg:   sdkms.AlgorithmRsa,
		Key:   &sobjDescriptor,
		Mode:  sdkms.CryptModeRSA(sdkms.RsaEncryptionPaddingOAEPMGF1(sdkms.DigestAlgorithmSha256)),
	}

	encryptResp, err := v.client.Encrypt(contxt, encryptReq)
	if err != nil {
		return nil, err
	}

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  FortanixDsmEnvelopeEncrypt,
			WrappedKey: encryptResp.Cipher,
		},
	}
	return ret, nil
}

func (v *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, errors.New("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("Key info is nil")
	}

	contxt := context.Background()
	sobjDescriptor := sdkms.SobjectDescriptor{
		Name: &v.keyName,
	}
	decryptReq := sdkms.DecryptRequest{
		Cipher: in.KeyInfo.WrappedKey,
		Key:    &sobjDescriptor,
		Mode:   sdkms.CryptModeRSA(sdkms.RsaEncryptionPaddingOAEPMGF1(sdkms.DigestAlgorithmSha256)),
	}
	decryptResp, err := v.client.Decrypt(contxt, decryptReq)
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        decryptResp.Plain,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	return wrapping.EnvelopeDecrypt(envInfo, opt...)

}

type sdkmsClient struct {
	*sdkms.Client
}

func (v *Wrapper) getDsmClient() (*sdkmsClient, error) {
	return &sdkmsClient{
		&sdkms.Client{
			HTTPClient: http.DefaultClient,
			Auth:       sdkms.APIKey(v.apiKey),
			Endpoint:   v.endpoint,
		}}, nil
}
