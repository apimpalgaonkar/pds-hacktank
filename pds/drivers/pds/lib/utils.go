package pds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	state "net/http"

	pdsapi "github.com/Madanagopal19/pds-hacktank/drivers/pds/api"
	pdscontrolplane "github.com/Madanagopal19/pds-hacktank/drivers/pds/controlplane"

	pds "github.com/portworx/pds-api-go-client/pds/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	//"github.com/portworx/sched-ops/k8s/apps"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	// clientset "k8s.io/client-go/kubernetes"
	// "k8s.io/kubernetes/test/e2e/framework"
	_ "github.com/lib/pq"
)

// BearerToken struct
type BearerToken struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint64 `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

const (
	storageTemplateName   = "Volume replication (best-effort spread)"
	resourceTemplateName  = "Small"
	appConfigTemplateName = "QaDefault"
	timeOut               = 5 * time.Minute
	timeInterval          = 10 * time.Second
	maxtimeInterval       = 30 * time.Second
	zookeeper             = "ZooKeeper"
	redis                 = "Redis"
	pdsSystemNamespace    = "pds-system"
	envControlPlaneURL    = "CONTROL_PLANE_URL"
	envPDSTestAccountName = "TEST_ACCOUNT_NAME"
	envTargetKubeconfig   = "TARGET_KUBECONFIG"
	envUsername           = "PDS_USERNAME"
	envPassword           = "PDS_PASSWORD"
	envPDSClientSecret    = "PDS_CLIENT_SECRET"
	envPDSClientID        = "PDS_CLIENT_ID"
	envPDSISSUERURL       = "PDS_ISSUER_URL"
	envClusterType        = "CLUSTER_TYPE"
)

var (

	//client             clientset.Interface
	apiClient                               *pds.APIClient
	components                              *pdsapi.Components
	deployment                              *pds.ModelsDeployment
	ns                                      *v1.Namespace
	accountID                               string
	tenantID                                string
	projectID                               string
	deploymentTargetID                      string
	storageTemplateID                       string
	currentReplicas                         int32
	err                                     error
	isavailable                             bool
	isTemplateavailable                     bool
	isVersionAvailable                      bool
	isBuildAvailable                        bool
	dataServiceVersionBuildMap              = make(map[string][]string)
	dataServiceDefaultResourceTemplateIDMap = make(map[string]string)
	dataServiceNameIDMap                    = make(map[string]string)
	dataServiceNameVersionMap               = make(map[string][]string)
	dataServiceIDImagesMap                  = make(map[string][]string)
	dataServiceNameDefaultAppConfigMap      = make(map[string]string)
	deploymentsMap                          = make(map[string][]*pds.ModelsDeployment)
	namespaceNameIDMap                      = make(map[string]string)
	kubeconfig                              = GetAndExpectStringEnvVar(envTargetKubeconfig)
	serviceType                             = "LoadBalancer"
)

var (
	host     string
	password string
	port     = 5432
	user     = "pds"
	dbname   = "MyDB"
)

// Environment lhasha
type Environment struct {
	PDSControlPlaneURL   string
	PDSTestAccountName   string
	PDSTargetKUBECONFIG  string
	PDSUsername          string
	PDSPassword          string
	PDSIssuerURL         string
	PDSClientID          string
	PDSClientSecret      string
	PDSTargetClusterType string
}

// MustHaveEnvVariables return emnvironment variables.
func MustHaveEnvVariables() Environment {
	return Environment{
		PDSControlPlaneURL:   mustGetEnvVariable(envControlPlaneURL),
		PDSTestAccountName:   mustGetEnvVariable(envPDSTestAccountName),
		PDSTargetKUBECONFIG:  mustGetEnvVariable(envTargetKubeconfig),
		PDSUsername:          mustGetEnvVariable(envUsername),
		PDSPassword:          mustGetEnvVariable(envPassword),
		PDSIssuerURL:         mustGetEnvVariable(envPDSISSUERURL),
		PDSClientID:          mustGetEnvVariable(envPDSClientID),
		PDSClientSecret:      mustGetEnvVariable(envPDSClientSecret),
		PDSTargetClusterType: mustGetEnvVariable(envClusterType),
	}
}

// mustGetEnvVariable return environment variable.
func mustGetEnvVariable(key string) string {
	value, isExist := os.LookupEnv(key)
	if !isExist {
		log.Panicf("Key: %v doesn't exist", key)
	}
	return value
}

// GetBearerToken fetches the token.
func GetBearerToken() (string, error) {
	username := os.Getenv(envUsername)
	password := os.Getenv(envPassword)
	clientID := os.Getenv(envPDSClientID)
	clientSecret := os.Getenv(envPDSClientSecret)
	issuerURL := os.Getenv(envPDSISSUERURL)
	url := fmt.Sprintf("%s/protocol/openid-connect/token", issuerURL)
	grantType := "password"

	postBody, err := json.Marshal(map[string]string{
		"grant_type":    grantType,
		"client_id":     clientID,
		"client_secret": clientSecret,
		"username":      username,
		"password":      password,
	})
	if err != nil {
		return "", err
	}
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(url, "application/json", requestBody)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var bearerToken = new(BearerToken)
	err = json.Unmarshal(body, &bearerToken)
	if err != nil {
		return "", err
	}
	return bearerToken.AccessToken, nil
}

// GetContext return context for api call.
func GetContext() (context.Context, error) {
	log.Info("Check for environmental variable.")
	envVars := MustHaveEnvVariables()
	endpointURL, err := url.Parse(envVars.PDSControlPlaneURL)
	if err != nil {
		log.Errorf("Unable to access the URL: %s", envVars.PDSControlPlaneURL)
		return nil, err
	}
	apiConf := pds.NewConfiguration()
	apiConf.Host = endpointURL.Host
	apiConf.Scheme = endpointURL.Scheme
	token, err := GetBearerToken()
	if err != nil {
		return nil, err
	}
	ctx := context.WithValue(context.Background(), pds.ContextAPIKeys, map[string]pds.APIKey{"ApiKeyAuth": {Key: token, Prefix: "Bearer"}})
	return ctx, nil
}

// GetAndExpectStringEnvVar parses a string from env variable.
func GetAndExpectStringEnvVar(varName string) string {
	varValue := os.Getenv(varName)
	return varValue
}

// GetAndExpectBoolEnvVar parses a boolean from env variable.
func GetAndExpectBoolEnvVar(varName string) (bool, error) {
	varValue := GetAndExpectStringEnvVar(varName)
	varBoolValue, err := strconv.ParseBool(varValue)
	return varBoolValue, err
}

// GetAndExpectIntEnvVar parses an int from env variable.
func GetAndExpectIntEnvVar(varName string) (int, error) {
	varValue := GetAndExpectStringEnvVar(varName)
	varIntValue, err := strconv.Atoi(varValue)
	return varIntValue, err
}

func ExecShellWithEnv(command string, envVars ...string) (string, string, error) {
	var stout, sterr []byte
	cmd := exec.Command("bash", "-c", command)
	log.Debug("Command %s ", command)
	cmd.Env = append(cmd.Env, envVars...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		log.Debug("Command %s failed to start. Cause: %v", command, err)
		return "", "", err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		stout, _ = copyAndCapture(os.Stdout, stdout)
		wg.Done()
	}()

	sterr, _ = copyAndCapture(os.Stderr, stderr)

	wg.Wait()

	err := cmd.Wait()
	return string(stout), string(sterr), err
}

func copyAndCapture(w io.Writer, r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			d := buf[:n]
			out = append(out, d...)
			_, err := w.Write(d)
			if err != nil {
				return out, err
			}
		}
		if err != nil {
			// Read returns io.EOF at the end of file, which is not an error for us
			if err == io.EOF {
				err = nil
			}
			return out, err
		}
	}
}

// Function to execute local command
func ExecShell(command string) (string, string, error) {
	return ExecShellWithEnv(command)
}

// GetClusterID retruns the cluster id for given targetClusterName
func GetClusterID(projectID string, targetClusterName string) (string, error) {

	deploymentTargets, err := components.DeploymentTarget.ListDeploymentTargetsBelongsToProject(projectID)
	if err != nil {
		log.Errorf("An Error Occured while listing deployment targets %v", err)
		return "", err
	}
	for index := range deploymentTargets {
		if deploymentTargets[index].GetName() == targetClusterName {
			return deploymentTargets[index].GetClusterId(), nil
		} else {
			cmd := fmt.Sprintf("kubectl get ns kube-system -o jsonpath={.metadata.uid} --kubeconfig %s", GetAndExpectStringEnvVar(envTargetKubeconfig))
			output, _, err := ExecShell(cmd)
			if err != nil {
				log.Error(err)
				return "Connection Refused!!", err
			}
			return output, nil
		}
	}
	return "", nil
}

// SetupPDSTest returns few params required to run the test
func SetupPDSTest(ControlPlaneURL, ClusterType, TargetClusterName, AccountName string) (string, string, string, string, string, string, string, error) {
	var err error
	apiConf := pds.NewConfiguration()
	endpointURL, err := url.Parse(ControlPlaneURL)
	if err != nil {
		log.Errorf("An Error Occured while parsing the URL %v", err)
		return "", "", "", "", "", "", "", err
	}
	apiConf.Host = endpointURL.Host
	apiConf.Scheme = endpointURL.Scheme

	apiClient = pds.NewAPIClient(apiConf)

	components = pdsapi.NewComponents(apiClient)
	controlplane := pdscontrolplane.NewControlPlane(ControlPlaneURL, components)

	if strings.EqualFold(ClusterType, "onprem") || strings.EqualFold(ClusterType, "ocp") {
		serviceType = "ClusterIP"
	}
	log.Infof("Deployment service type %s", serviceType)

	acc := components.Account
	accounts, err := acc.GetAccountsList()
	if err != nil {
		log.Errorf("An Error Occured while getting account list %v", err)
		return "", "", "", "", "", "", "", err
	}

	for i := 0; i < len(accounts); i++ {
		log.Infof("Account Name: %v", accounts[i].GetName())
		if accounts[i].GetName() == AccountName {
			accountID = accounts[i].GetId()
		}
	}
	log.Infof("Account Detail- Name: %s, UUID: %s ", AccountName, accountID)
	tnts := components.Tenant
	tenants, _ := tnts.GetTenantsList(accountID)
	tenantID = tenants[0].GetId()
	tenantName := tenants[0].GetName()
	log.Infof("Tenant Details- Name: %s, UUID: %s ", tenantName, tenantID)
	dnsZone, err := controlplane.GetDNSZone(tenantID)
	if err != nil {
		log.Errorf("Error while getting DNS Zone %v ", err)
		return "", "", "", "", "", "", "", err
	}
	log.Infof("DNSZone info - Name: %s, tenant: %s , account: %s", dnsZone, tenantName, AccountName)
	projcts := components.Project
	projects, _ := projcts.GetprojectsList(tenantID)
	projectID = projects[0].GetId()
	projectName := projects[0].GetName()
	log.Infof("Project Details- Name: %s, UUID: %s ", projectName, projectID)

	//To get clusterID of already registered target clusters
	clusterID, err := GetClusterID(projectID, TargetClusterName)
	if len(clusterID) > 0 {
		log.Infof("clusterID %v", clusterID)
	} else {
		log.Errorf("Cluster ID is empty %v", clusterID)
		return "", "", "", "", "", "", "", err
	}

	log.Info("Get the Target cluster details")
	targetClusters, err := components.DeploymentTarget.ListDeploymentTargetsBelongsToTenant(tenantID)
	if err != nil {
		log.Errorf("Error while listing deployments %v", err)
		return "", "", "", "", "", "", "", err
	}
	for i := 0; i < len(targetClusters); i++ {
		if targetClusters[i].GetClusterId() == clusterID {
			deploymentTargetID = targetClusters[i].GetId()
			log.Infof("Cluster ID: %v, Name: %v,Status: %v", targetClusters[i].GetClusterId(), targetClusters[i].GetName(), targetClusters[i].GetStatus())
		}
	}

	registrationToken, _ := controlplane.GetRegistrationToken(tenantID)

	return tenantID, dnsZone, projectID, serviceType, deploymentTargetID, clusterID, registrationToken, err
}

func IsNamespaceExist(name string, pathToKubeconfig string) bool {
	config, err := clientcmd.BuildConfigFromFlags("", pathToKubeconfig)
	if err != nil {
		log.Panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicf("k8s client creation failed with error %v", err)
	}

	ns, err := clientset.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Error while getting namespace %v ", err)

		return false
	}
	if ns.Name == name {
		log.Infof("Namespace %v ", ns.Name)
		kns, _ := clientset.CoreV1().Namespaces().Get(context.Background(), "kube-system", metav1.GetOptions{})
		log.Infof("Namespace UID %v ", kns.GetObjectMeta().GetUID())
		return true
	}
	return true
	//return !(errors.IsAlreadyExists(err) || errors.IsNotFound(err))
}

func isReachbale(url string) (bool, error) {
	timeout := time.Duration(15 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	_, err := client.Get(url)
	if err != nil {
		log.Error(err.Error())
		return false, err
	}
	return true, nil
}
func ListPods(namespace string, pathToKubeconfig string) []v1.Pod {
	config, err := clientcmd.BuildConfigFromFlags("", pathToKubeconfig)
	if err != nil {
		log.Panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic(err)
	}

	podList, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error(err)
	}
	return podList.Items
}

func isLatestHelm() bool {
	cmd := fmt.Sprintf(" helm ls --all -n pds-system --kubeconfig %s | tail -n+2 | awk '{print $8}' ", kubeconfig)
	output, _, err := ExecShell(cmd)
	if err != nil {
		log.Panic(err)
	}
	log.Info("Helm chart status - %v", output)
	return !strings.EqualFold(output, "pending-upgrade")

}
func WatchPodsStatus(namespace string, pathToKubeconfig string) {
	config, err := clientcmd.BuildConfigFromFlags("", pathToKubeconfig)
	if err != nil {
		log.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	watch, err := clientset.CoreV1().Pods(namespace).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err.Error())
	}
	go func() {
		for event := range watch.ResultChan() {
			log.Infof("Type: %v", event.Type)
			p, ok := event.Object.(*v1.Pod)
			if !ok {
				log.Panic("unexpected type")
			}
			log.Info(p.Status.ContainerStatuses)
			log.Info(p.Status.Phase)
		}
	}()
	time.Sleep(10 * time.Second)
}

func RegisterToControlPlane(controlPlaneUrl, tenantId, clusterType, bearerToken string) error {
	log.Info("Test control plane url connectivity.")
	_, err := isReachbale(controlPlaneUrl)
	if err != nil {
		return fmt.Errorf("unable to reach the control plane with following error - %v", err)
	}

	helmChartversion, err := components.APIVersion.GetHelmChartVersion()
	if err != nil {
		log.Errorf("Error while getting helm version %v", helmChartversion)
		return err
	}

	var cmd string
	apiEndpoint := fmt.Sprintf(controlPlaneUrl + "api")
	log.Infof("Verify if the namespace %s already exits.", pdsSystemNamespace)
	isExist := IsNamespaceExist(pdsSystemNamespace, kubeconfig)
	isRegistered := false
	if isExist {
		log.Infof("%s namespace already exists.", pdsSystemNamespace)
		pods := ListPods(pdsSystemNamespace, kubeconfig)
		if len(pods) > 0 {
			log.Warnf("Target cluster is already registered to control plane.")
			cmd = fmt.Sprintf("helm list -A --kubeconfig %s", kubeconfig)
			if !isLatestHelm() {
				log.Infof("Upgrading PDS helm chart from to %v", helmChartversion)

				cmd = fmt.Sprintf("helm upgrade --create-namespace --namespace=%s pds pds-target --repo=https://portworx.github.io/pds-charts --version=%s --set tenantId=%s "+
					"--set bearerToken=%s --set apiEndpoint=%s --kubeconfig %s", pdsSystemNamespace, helmChartversion, tenantId, bearerToken, apiEndpoint, kubeconfig)

			}
			isRegistered = true
		}
	}

	if !isRegistered {
		log.Infof("Installing PDS ( helm version -  %v)", helmChartversion)
		if strings.EqualFold(clusterType, "ocp") {
			cmd = fmt.Sprintf("helm install --create-namespace --namespace=%s pds pds-target --repo=https://portworx.github.io/pds-charts --version=%s --set platform=ocp --set tenantId=%s "+
				"--set bearerToken=%s --set apiEndpoint=%s --kubeconfig %s", pdsSystemNamespace, helmChartversion, tenantId, bearerToken, apiEndpoint, kubeconfig)
		} else {
			cmd = fmt.Sprintf("helm install --create-namespace --namespace=%s pds pds-target --repo=https://portworx.github.io/pds-charts --version=%s --set tenantId=%s "+
				"--set bearerToken=%s --set apiEndpoint=%s --kubeconfig %s", pdsSystemNamespace, helmChartversion, tenantId, bearerToken, apiEndpoint, kubeconfig)
		}

		log.Infof("helm command %v ", cmd)

	}
	output, _, err := ExecShell(cmd)
	if err != nil {
		log.Warn("Kindly remove the PDS chart properly and retry. CMD>> helm uninstall  pds --namespace pds-system --kubeconfig $KUBECONFIG")
		log.Error(err)
		return err
	}
	log.Infof("Terminal output -> %v", output)
	time.Sleep(20 * time.Second)
	log.Infof("Watch states of pods in %s namespace", pdsSystemNamespace)
	WatchPodsStatus(pdsSystemNamespace, kubeconfig)

	time.Sleep(20 * time.Second)
	log.Infof("Verify the health of all the pods in %s namespace", pdsSystemNamespace)
	CheckPodsHealth(pdsSystemNamespace, kubeconfig)
	return err
}

func CheckPodsHealth(namespace string, pathToKubeconfig string) {
	config, err := clientcmd.BuildConfigFromFlags("", pathToKubeconfig)
	if err != nil {
		log.Panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic(err)
	}
	pods := ListPods(namespace, pathToKubeconfig)
	log.Infof("There are %d pods present in the namespace %s", len(pods), namespace)
	for _, pod := range pods {
		_, err = clientset.CoreV1().Pods(namespace).Get(context.TODO(), pod.GetName(), metav1.GetOptions{})
		if errors.IsNotFound(err) {
			log.Panicf("Pod %s in namespace %s not found", pod.GetName(), namespace)
		} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
			log.Errorf("Found pod %s (Namespace -  %s) in unhealthy state.", pod.GetName(), namespace)
			log.Panicf("Error getting pod %s in namespace %s: %v",
				pod.GetName(), namespace, statusError.ErrStatus.Message)
		} else if err != nil {
			log.Errorf("Found pod %s (Namespace -  %s) in unhealthy state.", pod.GetName(), namespace)
			log.Panic(err)
		} else {
			log.Infof("Found pod %s (Namespace -  %s) in healthy state.", pod.GetName(), namespace)
		}
		time.Sleep(1 * time.Second)
	}
}

func RegisterTargetClusterToPDS(tenantID, clusterID, targetClusterName string) error {
	helmVersion, err := components.APIVersion.GetHelmChartVersion()
	if err != nil {
		log.Errorf("Error while getting helm version %v", helmVersion)
		return err
	}
	log.Infof("helm chart version %v ", helmVersion)
	dt, _, err := components.DeploymentTarget.CreateTarget(tenantID, clusterID, targetClusterName)
	if err != nil {
		log.Errorf("Error while registering deployment target %v", err)
		return err
	}

	log.Infof("deploymentTarget ID %v ", dt.GetId())

	err = wait.Poll(maxtimeInterval, timeOut, func() (bool, error) {
		log.Infof("Target Cluster Registeration inprocess")
		targetCluster, err := components.DeploymentTarget.GetTarget(dt.GetId())
		if err != nil {
			log.Errorf("Error occured while getting deployment target status %v", err)
			return false, nil
		}
		if targetCluster.GetStatus() != "healthy" {
			return false, nil
		}
		return true, nil
	})
	if err == nil {
		log.Infof("Target Cluster Registered successfully to the control plane")
	}

	return err
}

// GetnameSpaceID returns the namespace ID
func GetnameSpaceID(namespace string, deploymentTargetID string) (string, error) {
	var namespaceID string

	err = wait.Poll(timeInterval, timeOut, func() (bool, error) {
		log.Infof("Listing Available namespace")
		namespaces, err := components.Namespace.ListNamespaces(deploymentTargetID)
		if err != nil {
			log.Errorf("An Error Occured while listing namespaces %v", err)
			return false, err
		}
		for i := 0; i < len(namespaces); i++ {
			if namespaces[i].GetStatus() == "available" {
				if namespaces[i].GetName() == namespace {
					namespaceID = namespaces[i].GetId()
					namespaceNameIDMap[namespaces[i].GetName()] = namespaces[i].GetId()
					log.Infof("Available namespace - Name: %v , Id: %v , Status: %v", namespaces[i].GetName(), namespaces[i].GetId(), namespaces[i].GetStatus())
					return true, nil
				}
			}
		}
		return true, nil

	})
	return namespaceID, nil
}

// GetStorageTemplate return the storage template id
func GetStorageTemplate(tenantID string) (string, error) {
	log.Infof("Get the storage template")
	storageTemplates, err := components.StorageSettingsTemplate.ListTemplates(tenantID)
	if err != nil {
		log.Errorf("Error while listing storage template %v", err)
		return "", err
	}
	for i := 0; i < len(storageTemplates); i++ {
		if storageTemplates[i].GetName() == storageTemplateName {
			log.Infof("Storage template details -----> Name %v,Repl %v , Fg %v , Fs %v",
				storageTemplates[i].GetName(),
				storageTemplates[i].GetRepl(),
				storageTemplates[i].GetFg(),
				storageTemplates[i].GetFs())
			storageTemplateID = storageTemplates[i].GetId()
			log.Infof("Storage Id: %v", storageTemplateID)
		}
	}
	return storageTemplateID, nil
}

// GetAppConfTemplate returns the app config templates
func GetAppConfTemplate(tenantID string, dataServiceNameIDMap map[string]string) (map[string]string, error) {
	appConfigs, err := components.AppConfigTemplate.ListTemplates(tenantID)
	if err != nil {
		return nil, err
	}
	isavailable = false
	isTemplateavailable = false
	for i := 0; i < len(appConfigs); i++ {
		if appConfigs[i].GetName() == appConfigTemplateName {
			isTemplateavailable = true
			for key := range dataServiceNameIDMap {
				if dataServiceNameIDMap[key] == appConfigs[i].GetDataServiceId() {
					dataServiceNameDefaultAppConfigMap[key] = appConfigs[i].GetId()
					isavailable = true
				}
			}
		}
	}
	if !(isavailable && isTemplateavailable) {
		log.Errorf("App Config Template with name %v does not exist", appConfigTemplateName)
	}
	return dataServiceNameDefaultAppConfigMap, nil
}

// GetResourceTemplate get the resource template id and forms supported dataserviceNameIdMap
func GetResourceTemplate(tenantID string, supportedDataServices []string) (map[string]string, map[string]string, error) {
	log.Infof("Get the resource template for each data services")
	resourceTemplates, err := components.ResourceSettingsTemplate.ListTemplates(tenantID)
	if err != nil {
		return nil, nil, err
	}
	isavailable = false
	isTemplateavailable = false
	for i := 0; i < len(resourceTemplates); i++ {
		if resourceTemplates[i].GetName() == resourceTemplateName {
			isTemplateavailable = true
			dataService, err := components.DataService.GetDataService(resourceTemplates[i].GetDataServiceId())
			if err != nil {
				return nil, nil, err
			}
			for dataKey := range supportedDataServices {
				if dataService.GetName() == supportedDataServices[dataKey] {
					log.Infof("Data service name: %v", dataService.GetName())
					log.Infof("Resource template details ---> Name %v, Id : %v ,DataServiceId %v , StorageReq %v , Memoryrequest %v",
						resourceTemplates[i].GetName(),
						resourceTemplates[i].GetId(),
						resourceTemplates[i].GetDataServiceId(),
						resourceTemplates[i].GetStorageRequest(),
						resourceTemplates[i].GetMemoryRequest())

					dataServiceDefaultResourceTemplateIDMap[dataService.GetName()] =
						resourceTemplates[i].GetId()
					dataServiceNameIDMap[dataService.GetName()] = dataService.GetId()
					isavailable = true
				}
			}
		}
	}
	if !(isavailable && isTemplateavailable) {
		log.Errorf("Template with Name %v does not exis", resourceTemplateName)
	}
	return dataServiceDefaultResourceTemplateIDMap, dataServiceNameIDMap, nil
}

// GetVersionsImage returns the required Image of dataservice version
func GetVersionsImage(dsVersion string, dsBuild string, dataServiceID string, getAllImages bool) (map[string][]string, map[string][]string, error) {
	var versions []pds.ModelsVersion
	var images []pds.ModelsImage

	versions, err = components.Version.ListDataServiceVersions(dataServiceID)
	if err != nil {
		return nil, nil, err
	}
	isVersionAvailable = false
	isBuildAvailable = false
	for i := 0; i < len(versions); i++ {
		if (*versions[i].Enabled) && (*versions[i].Name == dsVersion) {
			images, _ = components.Image.ListImages(versions[i].GetId())
			for j := 0; j < len(images); j++ {
				if !getAllImages && *images[j].Build == dsBuild {
					dataServiceIDImagesMap[versions[i].GetId()] = append(dataServiceIDImagesMap[versions[i].GetId()], images[j].GetId())
					dataServiceVersionBuildMap[versions[i].GetName()] = append(dataServiceVersionBuildMap[versions[i].GetName()], images[j].GetBuild())
					isBuildAvailable = true
					break //remove this break to deploy all images for selected version
				} else if getAllImages {
					dataServiceIDImagesMap[versions[i].GetId()] = append(dataServiceIDImagesMap[versions[i].GetId()], images[j].GetId())
					dataServiceVersionBuildMap[versions[i].GetName()] = append(dataServiceVersionBuildMap[versions[i].GetName()], images[j].GetBuild())
					isBuildAvailable = true
				}
			}
			isVersionAvailable = true
			break
		}
	}
	if !(isVersionAvailable && isBuildAvailable) {
		log.Errorf("Version/Build passed is not available")
	}

	for key := range dataServiceVersionBuildMap {
		log.Infof("Version - %v,Build - %v", key, dataServiceVersionBuildMap[key])
	}

	for key := range dataServiceIDImagesMap {
		log.Infof("DS Verion id - %v, DS Image id - %v", key, dataServiceIDImagesMap[key])
	}
	return dataServiceNameVersionMap, dataServiceIDImagesMap, nil
}

// GetAllVersionsImages returns all the versions and Images of dataservice
func GetAllVersionsImages(dataServiceID string) (map[string][]string, map[string][]string, error) {
	var versions []pds.ModelsVersion
	var images []pds.ModelsImage

	versions, err = components.Version.ListDataServiceVersions(dataServiceID)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < len(versions); i++ {
		if *versions[i].Enabled {
			images, _ = components.Image.ListImages(versions[i].GetId())
			for j := 0; j < len(images); j++ {
				dataServiceIDImagesMap[versions[i].GetId()] = append(dataServiceIDImagesMap[versions[i].GetId()], images[j].GetId())
				dataServiceVersionBuildMap[versions[i].GetName()] = append(dataServiceVersionBuildMap[versions[i].GetName()], images[j].GetBuild())
			}
		}
	}

	for key := range dataServiceVersionBuildMap {
		log.Infof("Version - %v,Build - %v", key, dataServiceVersionBuildMap[key])
	}
	for key := range dataServiceIDImagesMap {
		log.Infof("DS Verion id - %v,DS Image id - %v", key, dataServiceIDImagesMap[key])
	}
	return dataServiceNameVersionMap, dataServiceIDImagesMap, nil
}

// ValidateDataServiceDeployment checks if deployment is healthy and running
func ValidateDataServiceDeployment(deployment *pds.ModelsDeployment) error {

	err = wait.Poll(maxtimeInterval, timeOut, func() (bool, error) {
		status, res, err := components.DataServiceDeployment.GetDeploymentStatus(deployment.GetId())
		log.Infof("Health status -  %v", status.GetHealth())
		if err != nil {
			log.Errorf("Error occured while getting deployment status %v", err)
			return false, nil
		}
		if res.StatusCode != state.StatusOK {
			log.Errorf("Error when calling `ApiDeploymentsIdCredentialsGet``: %v\n", err)
			log.Errorf("Full HTTP response: %v\n", res)
			return false, err
		}
		if status.GetHealth() != "Healthy" {
			return false, nil
		}
		log.Infof("Deployment details: Health status -  %v,Replicas - %v, Ready replicas - %v", status.GetHealth(), status.GetReplicas(), status.GetReadyReplicas())
		return true, nil

	})
	return err
}

// DeployDataServices deploys all dataservices, versions and images that are supported
func DeployDataServices(supportedDataServicesMap map[string]string, projectID, deploymentTargetID, dnsZone, deploymentName, namespaceID string,
	dataServiceNameDefaultAppConfigMap map[string]string, replicas int32, serviceType string, dataServiceDefaultResourceTemplateIDMap map[string]string,
	storageTemplateID string, deployAllVersions, getAllImages bool, dsVersion, dsBuild string) (map[string][]*pds.ModelsDeployment, map[string][]string, map[string][]string, error) {

	currentReplicas = replicas
	var dataServiceImageMap map[string][]string

	for ds, id := range supportedDataServicesMap {
		log.Infof("dataService: %v ", ds)
		log.Infof(`Request params:
				projectID- %v deploymentTargetID - %v,
				dnsZone - %v,deploymentName - %v,namespaceID - %v
				App config ID - %v,
				num pods- %v, service-type - %v
				Resource template id - %v, storageTemplateID - %v`,
			projectID, deploymentTargetID, dnsZone, deploymentName, namespaceID, dataServiceNameDefaultAppConfigMap[ds],
			replicas, serviceType, dataServiceDefaultResourceTemplateIDMap[ds], storageTemplateID)

		if ds == zookeeper && replicas != 3 {
			log.Warnf("Zookeeper replicas cannot be %v, it should be 3", replicas)
			currentReplicas = 3
		}
		if ds == redis {
			log.Infof("Replicas passed %v", replicas)
			log.Warnf("Redis deployment replicas should be any one of the following values 1, 6, 8 and 10")
		}

		//clearing up the previous entries of dataServiceImageMap
		for ds := range dataServiceImageMap {
			delete(dataServiceImageMap, ds)
		}

		if !deployAllVersions {
			log.Infof("Getting versionID  for Data service version %s and buildID for %s ", dsVersion, dsBuild)
			dataServiceVersionBuildMap, dataServiceImageMap, err = GetVersionsImage(dsVersion, dsBuild, id, getAllImages)
			if err != nil {
				return nil, nil, nil, err
			}
		} else {
			dataServiceVersionBuildMap, dataServiceImageMap, err = GetAllVersionsImages(id)
			if err != nil {
				return nil, nil, nil, err
			}
		}

		for version := range dataServiceImageMap {
			for index := range dataServiceImageMap[version] {
				imageID := dataServiceImageMap[version][index]
				log.Infof("VersionID %v ImageID %v", version, imageID)
				components = pdsapi.NewComponents(apiClient)
				deployment, err = components.DataServiceDeployment.CreateDeployment(projectID,
					deploymentTargetID,
					dnsZone,
					deploymentName,
					namespaceID,
					dataServiceNameDefaultAppConfigMap[ds],
					imageID,
					currentReplicas,
					serviceType,
					dataServiceDefaultResourceTemplateIDMap[ds],
					storageTemplateID)

				if err != nil {
					log.Warnf("An Error Occured while creating deployment %v", err)
					return nil, nil, nil, err
				}
				err = ValidateDataServiceDeployment(deployment)
				if err != nil {
					return nil, nil, nil, err
				}
				deploymentsMap[ds] = append(deploymentsMap[ds], deployment)
			}
		}
	}
	return deploymentsMap, dataServiceImageMap, dataServiceVersionBuildMap, nil
}

// CheckNamespace checks if the namespace is available in the cluster and pds is enabled on it
func CheckNamespace(namespace string) (bool, error) {

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns, err = clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	isavailable = false
	if err != nil {
		log.Warnf("Error while getting namespace %v", err)
		if strings.Contains(err.Error(), "not found") {
			nsName := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   namespace,
					Labels: map[string]string{"pds.portworx.com/available": "true"},
				},
			}
			log.Infof("Creating namespace %v", namespace)
			ns, err = clientset.CoreV1().Namespaces().Create(ctx, nsName, metav1.CreateOptions{})
			if err != nil {
				log.Errorf("Error while creating namespace %v", err)
				return false, err
			}
			isavailable = true
		}
		if !isavailable {
			return false, err
		}
	}

	log.Infof("namspaceID %v ", string(ns.GetObjectMeta().GetUID()))
	isavailable = false
	for key, value := range ns.Labels {
		log.Infof("key: %v values: %v", key, value)
		if key == "pds.portworx.com/available" && value == "true" {
			isavailable = true
			break
		}
	}
	if !isavailable {
		return false, nil
	}

	return true, nil
}
