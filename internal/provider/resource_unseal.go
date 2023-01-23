package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	api "github.com/hashicorp/vault/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const (
	argSecretSharesUnseal    = "secret_shares"
	argSecretThresholdUnseal = "secret_threshold"
	argKeysUnseal            = "unseal_keys"
)

func resourceUnseal() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Resource for vault operator init",

		CreateContext: resourceUnsealCreate,
		ReadContext:   resourceUnsealRead,
		UpdateContext: resourceUnsealUpdate,
		DeleteContext: resourceUnsealDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceUnsealImporter,
		},

		Schema: map[string]*schema.Schema{
			argSecretSharesUnseal: {
				Description: "Specifies the number of shares to split the master key into.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			argSecretThresholdUnseal: {
				Description: "Specifies the number of shares required to reconstruct the master key.",
				Type:        schema.TypeInt,
				Optional:    true,
			},
			argKeysUnseal: {
				Description: "The unseal keys.",
				Type:        schema.TypeList,
				Optional:    false,
			},
		},
	}
}

func resourceUnsealCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	client := meta.(*apiClient)
	// SecretThresholdUnseal := d.Get(argSecretThresholdUnseal).(int)
	// SecretSharesUnseal := d.Get(argSecretSharesUnseal).(int)
	KeysUnseal := d.Get(argKeysUnseal).([]interface{})

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
	Keys_UnsealList := make([]string, len(KeysUnseal))
	for i := range Keys_UnsealList {

		req := api.UnsealOpts{
			Key: Keys_UnsealList[i],
		}

		logDebug("request: %v", req)

		res, err := client.client.Sys().UnsealWithOptions(&req)

		if err != nil {
			logError("failed to unseal Vault: %v", err)
			return diag.FromErr(err)
		}

		logDebug("response: %v", res)
	}
	close(stopCh)

	return diag.Diagnostics{}
}

func resourceUnsealRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	return diag.Diagnostics{}
}

func resourceUnsealUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	return diag.Diagnostics{}
}

func resourceUnsealDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	// client := meta.(*apiClient)

	return diag.Diagnostics{}
}

func resourceUnsealImporter(c context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	// client := meta.(*apiClient)
	// Id should be a file scheme URL: file://path_to_file.json
	// The json file schema should be the same as what's returned from the sys/init API (i.e. a InitResponse)
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

	fc, err := ioutil.ReadFile(filepath.Join(u.Host, u.Path))
	if err != nil {
		logError("failed reading file %v", err)
		return nil, err
	}

	var unsealResponse api.SealStatusResponse
	if err := json.Unmarshal(fc, &unsealResponse); err != nil {
		logError("failed unmarshalling json: %v", err)
		return nil, err
	}

	// if err := updateState(d, client.client.Address(), &unsealResponse); err != nil {
	// 	logError("failed to update state: %v", err)
	// 	return nil, err
	// }

	return []*schema.ResourceData{d}, nil
}
