package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
		Description: "Resource for vault operator unseal",

		CreateContext: resourceUnsealCreate,
		ReadContext:   resourceUnsealRead,
		UpdateContext: resourceUnsealUpdate,
		DeleteContext: resourceUnsealDelete,
		Schema: map[string]*schema.Schema{
			argSecretSharesUnseal: {
				Description: "Specifies the number of shares the master key was split  into.",
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
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
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
	stopCh := make(chan struct{}, 1)
	readyCh := make(chan struct{})

	if kubeConfig := client.kubeConn.kubeConfig; kubeConfig != nil {
		kubeClientSet := client.kubeConn.kubeClient
		nameSpace := client.kubeConn.nameSpace
		serviceName := client.kubeConn.serviceName
		localPort := client.kubeConn.localPort
		remotePort := client.kubeConn.remotePort

		errCh := make(chan error, 1)
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
	for i, unseal_key := range KeysUnseal {
		Keys_UnsealList[i] = unseal_key.(string)
		res, err := client.client.Sys().Unseal(Keys_UnsealList[i])

		if err != nil {
			logError("failed to unseal Vault: %v", err)
			return diag.FromErr(err)
		}

		logDebug("response: %v", res)
	}
	if err := updateStateUnseal(d, client.client.Address()); err != nil {
		logError("failed to update state: %v", err)
		return diag.FromErr(err)
	}
	close(stopCh)

	return diag.Diagnostics{}
}

func resourceUnsealRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func resourceUnsealUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func resourceUnsealDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func updateStateUnseal(d *schema.ResourceData, id string) error {
	d.SetId(id)
	return nil
}
