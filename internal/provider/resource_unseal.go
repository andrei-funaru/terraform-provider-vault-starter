package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/openpgp"
	combin "gonum.org/v1/gonum/stat/combin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const (
	argSecretShares    = "secret_shares"
	argSecretThreshold = "secret_threshold"
	argKeys            = "keys"
	argPGPKeys         = "pgp_keys"
	argpassphrase      = "passphrase"
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
			argSecretShares: {
				Description: "Specifies the number of shares the master key was split  into.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     5,
			},
			argSecretThreshold: {
				Description: "Specifies the number of shares required to reconstruct the master key.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     3,
			},
			argKeys: {
				Description: "The unseal keys.",
				Type:        schema.TypeList,
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argPGPKeys: {
				Description: "Specifies an array of PGP public keys used to decript the unseal keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as secret_shares.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argpassphrase: {
				Description: "Specifies an array of PGP public keys passphrase used to decript the unseal keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as secret_shares.",
				Type:        schema.TypeList,
				Optional:    true,
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
	pgpKeys := d.Get(argPGPKeys).([]interface{})
	Keys := d.Get(argKeys).([]interface{})
	SecretShares := d.Get(argSecretShares).(int)
	SecretThreshold := d.Get(argSecretThreshold).(int)
	passphrase := d.Get(argpassphrase).([]interface{})
	stopCh := make(chan struct{}, 1)
	readyCh := make(chan struct{})

	pgpKeysList := make([]string, len(pgpKeys))
	for i, pgpKey := range pgpKeys {
		pgpKeysList[i] = pgpKey.(string)
	}

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
	KeysList := make([]string, len(Keys))
	for i, key := range Keys {
		if len(pgpKeys) != 0 {
			decripted_key, err := get_decrypted_key(pgpKeys[i].(string), passphrase[i].(string), key.(string))
			if err != nil {
				logError("failed to unseal Vault: %v", err)
				return diag.FromErr(err)
			}
			KeysList[i] = decripted_key
		} else {
			KeysList[i] = key.(string)
		}
	}
	array := get_index_for_keys(SecretShares, SecretThreshold)

	for i := 0; i < len(array); i++ {
		res, err := client.client.Sys().Unseal(KeysList[array[i]])
		if err != nil {
			logError("failed to unseal Vault: %v", err)
			return diag.FromErr(err)
		}

		logDebug("response: %v", res)
	}
	if err := updateStateUnseal(d, "create_unseal"); err != nil {
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

func get_index_for_keys(shares int, threshold int) []int {
	rand.Seed(time.Now().UnixNano())
	combos := combin.Combinations(shares, threshold)
	number := rand.Intn(len(combos))
	fmt.Println(combos[number])
	result := combos[number]
	return result
}

func get_decrypted_key(private_key_path string, passphrase string, encString string) (string, error) {

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(private_key_path)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)

	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}
