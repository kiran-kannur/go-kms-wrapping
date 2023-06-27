package fortanixdsm

import (
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"strconv"
)

// options = how options are represented
type options struct {
	*wrapping.Options

	withDisallowEnvVars bool
	withKeyNotRequired  bool
	withApikey          string
	withKeyId           string
	withKeyName         string
	withEndpoint        string
	withLogger          hclog.Logger
}

func getDefaultOptions() options {
	return options{}
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "disallow_env_vars":
				disallowEnvVars, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withDisallowEnvVars = disallowEnvVars
			case "key_not_required":
				keyNotRequired, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				opts.withKeyNotRequired = keyNotRequired
			case "apiKey":
				opts.withApikey = v
			case "keyId":
				opts.withKeyId = v
			case "endpoint":
				opts.withEndpoint = v
			case "keyName":
				opts.withKeyName = v
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	return &opts, nil
}

// WithApiKeyprovides way to disable using env vars
func WithApiKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withApikey = with
			return nil
		})
	}
}

// WithKeyId provides a way to chose the client ID
func withKeyId(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyId = with
			return nil
		})
	}
}

// WithKeyName provides a way to chose the client ID
func withKeyName(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyName = with
			return nil
		})
	}
}
