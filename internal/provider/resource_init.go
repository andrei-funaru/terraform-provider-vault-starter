package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	api "github.com/hashicorp/vault/api"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const (
	argSecretSharesInit       = "secret_shares"
	argSecretThresholdInit    = "secret_threshold"
	argStoredSharesInit       = "stored_shares"
	argRecoverySharesInit     = "recovery_shares"
	argRecoveryThresholdInit  = "recovery_threshold"
	argRecoveryKeysInit       = "recovery_keys"
	argRecoveryKeysBase64Init = "recovery_keys_base64"
	argRootTokenInit          = "root_token"
	argKeysInit               = "init_keys"
	argKeysBase64Init         = "keys_base64"
	argPGPKeysInit            = "pgp_keys"
	argRecoveryPGPKeysInit    = "recovery_pgp_keys"
	argRootTokenPGPKeyInit    = "root_token_pgp_key"
)

func resourceInit() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Resource for vault operator init",

		CreateContext: resourceInitCreate,
		ReadContext:   resourceInitRead,
		UpdateContext: resourceInitUpdate,
		DeleteContext: resourceInitDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceInitImporter,
		},

		Schema: map[string]*schema.Schema{
			argSecretSharesInit: {
				Description: "Specifies the number of shares to split the master key into.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     5,
			},
			argSecretThresholdInit: {
				Description: "Specifies the number of shares required to reconstruct the master key.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     3,
			},
			argRecoverySharesInit: {
				Description: "Specifies the number of shares to split the recovery key into.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			argRecoveryThresholdInit: {
				Description: "Specifies the number of shares required to reconstruct the recovery key.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			argPGPKeysInit: {
				Description: "Specifies an array of PGP public keys used to encrypt the output unseal keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as secret_shares.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argRecoveryPGPKeysInit: {
				Description: "Specifies an array of PGP public keys used to encrypt the output recovery keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as recovery_shares. This is only available when using Auto Unseal.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argRootTokenPGPKeyInit: {
				Description: "Specifies a PGP public key used to encrypt the initial root token. The key must be base64-encoded from its original binary representation.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			argRootTokenInit: {
				Description: "The Vault Root Token.",
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
			},
			argKeysInit: {
				Description: "The unseal keys.",
				Type:        schema.TypeList,
				Computed:    true,
				Sensitive:   true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argKeysBase64Init: {
				Description: "The unseal keys, base64 encoded.",
				Type:        schema.TypeList,
				Computed:    true,
				Sensitive:   true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argRecoveryKeysInit: {
				Description: "The recovery keys",
				Type:        schema.TypeList,
				Computed:    true,
				Sensitive:   true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argRecoveryKeysBase64Init: {
				Description: "The recovery keys, base64 encoded.",
				Type:        schema.TypeList,
				Computed:    true,
				Sensitive:   true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceInitCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	client := meta.(*apiClient)
	secretShares := d.Get(argSecretSharesInit).(int)
	secretThreshold := d.Get(argSecretThresholdInit).(int)
	recoveryShares := d.Get(argRecoverySharesInit).(int)
	recoveryThreshold := d.Get(argRecoveryThresholdInit).(int)
	pgpKeys := d.Get(argPGPKeysInit).([]interface{})
	recoveryPGPKeys := d.Get(argRecoveryPGPKeysInit).([]interface{})
	rootTokenPGPKey := d.Get(argRootTokenPGPKeyInit).(string)

	pgpKeysList := make([]string, len(pgpKeys))
	for i, pgpKey := range pgpKeys {
		pgpKeysList[i] = pgpKey.(string)
	}

	recoveryPGPKeysList := make([]string, len(recoveryPGPKeys))
	for i, pgpKey := range recoveryPGPKeys {
		recoveryPGPKeysList[i] = pgpKey.(string)
	}

	// stopCh control the port forwarding lifecycle. When it gets closed the
	// port forward will terminate
	stopCh := make(chan struct{}, 1)
	// readyCh communicate when the port forward is ready to get traffic
	readyCh := make(chan struct{})

	if kubeConfig := client.kubeConn.kubeConfig; kubeConfig != nil {
		kubeClientSet := client.kubeConn.kubeClient
		nameSpace := client.kubeConn.nameSpace
		serviceName := client.kubeConn.serviceName
		localPort := client.kubeConn.localPort
		remotePort := client.kubeConn.remotePort

		errCh := make(chan error, 1)

		// managing termination signal from the terminal. As you can see the stopCh
		// gets closed to gracefully handle its termination.
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			logInfo("Stopping a forward process...")
			close(stopCh)
		}()

		go func() {
			svc, err := kubeClientSet.CoreV1().Services(nameSpace).Get(ctx, serviceName, metav1.GetOptions{})
			if err != nil {
				logDebug("failed to create Kubernetes client")
				errCh <- err
			}

			selector := mapToSelectorStr(svc.Spec.Selector)
			if selector == "" {
				logDebug("failed to get service selector")
				errCh <- err
			}

			pods, err := kubeClientSet.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
			if err != nil {
				logDebug("failed to get a pod list")
				errCh <- err
			}

			if len(pods.Items) == 0 {
				logDebug("no Vault pods was found")
				errCh <- err
			}

			livePod, err := getPodName(pods)
			if err != nil {
				logDebug("failed to get live Vault pod")
				errCh <- err
			}

			serverURL, err := url.Parse(
				fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/portforward", kubeConfig.Host, nameSpace, livePod))
			if err != nil {
				logDebug("failed to construct server url")
				errCh <- err
			}

			transport, upgrader, err := spdy.RoundTripperFor(kubeConfig)
			if err != nil {
				logDebug("failed to create a round tripper")
				errCh <- err
			}

			dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, serverURL)

			addresses := []string{"127.0.0.1"}
			ports := []string{fmt.Sprintf("%s:%s", localPort, remotePort)}

			pf, err := portforward.NewOnAddresses(
				dialer,
				addresses,
				ports,
				stopCh,
				readyCh,
				os.Stdout,
				os.Stderr)
			if err != nil {
				logDebug("failed to create port-forward: %s:%s", localPort, remotePort)
				errCh <- err
			}

			go pf.ForwardPorts()

			<-readyCh

			actualPorts, err := pf.GetPorts()
			if err != nil {
				logDebug("failed to get port-forward ports")
				errCh <- err
			}
			if len(actualPorts) != 1 {
				logDebug("cannot get forwarded ports: unexpected length %d", len(actualPorts))
				errCh <- err
			}
		}()

		select {
		case <-readyCh:
			logDebug("Port-forwarding is ready to handle traffic")
			break
		case err := <-errCh:
			return diag.FromErr(err)
		}
	}

	req := api.InitRequest{
		SecretShares:      secretShares,
		SecretThreshold:   secretThreshold,
		RecoveryShares:    recoveryShares,
		RecoveryThreshold: recoveryThreshold,
		PGPKeys:           pgpKeysList,
		RecoveryPGPKeys:   recoveryPGPKeysList,
		RootTokenPGPKey:   rootTokenPGPKey,
	}

	logDebug("request: %v", req)

	res, err := client.client.Sys().Init(&req)

	if err != nil {
		logError("failed to initialize Vault: %v", err)
		return diag.FromErr(err)
	}

	logDebug("response: %v", res)

	if err := updateState(d, client.client.Address(), res); err != nil {
		logError("failed to update state: %v", err)
		return diag.FromErr(err)
	}

	close(stopCh)

	return diag.Diagnostics{}
}

func resourceInitRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func resourceInitUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func resourceInitDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func resourceInitImporter(c context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	client := meta.(*apiClient)
	id := d.Id()

	u, err := url.Parse(id)
	if err != nil {
		logError("failed parsing id url %v", err)
		return nil, err
	}

	if u.Scheme != "file" {
		logError("unsupported scheme")
		return nil, errors.New("unsupported scheme")
	}

	fc, err := os.ReadFile(filepath.Join(u.Host, u.Path))
	if err != nil {
		logError("failed reading file %v", err)
		return nil, err
	}

	var initResponse api.InitResponse
	if err := json.Unmarshal(fc, &initResponse); err != nil {
		logError("failed unmarshalling json: %v", err)
		return nil, err
	}

	if err := updateState(d, client.client.Address(), &initResponse); err != nil {
		logError("failed to update state: %v", err)
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func updateState(d *schema.ResourceData, id string, res *api.InitResponse) error {
	d.SetId(id)

	if err := d.Set(argRootTokenInit, res.RootToken); err != nil {
		return err
	}
	if err := d.Set(argKeysInit, res.Keys); err != nil {
		return err
	}
	if err := d.Set(argKeysBase64Init, res.KeysB64); err != nil {
		return err
	}
	if err := d.Set(argRecoveryKeysInit, res.RecoveryKeys); err != nil {
		return err
	}
	if err := d.Set(argRecoveryKeysBase64Init, res.RecoveryKeysB64); err != nil {
		return err
	}

	return nil
}

func getPodName(pods *v1.PodList) (string, error) {

	for _, pod := range pods.Items {
		if pod.Status.Phase != v1.PodRunning {
			continue
		}

		return pod.Name, nil
	}

	return "", fmt.Errorf("no live pods behind the service")
}

func mapToSelectorStr(msel map[string]string) string {
	selector := ""
	for k, v := range msel {
		if selector != "" {
			selector = selector + ","
		}
		selector = selector + fmt.Sprintf("%s=%s", k, v)
	}

	return selector
}
