package main

import (
	pdslib "github.com/Madanagopal19/pds-hacktank/drivers/pds/lib"
	pds "github.com/portworx/pds-api-go-client/pds/v1alpha1"

	log "github.com/sirupsen/logrus"
)

const (
	deploymentName           = "qa"
	envDsVersion             = "DS_VERSION"
	envDsBuild               = "DS_BUILD"
	envReplicas              = "NO_OF_NODES"
	envNamespace             = "NAMESPACE"
	envDataService           = "DATA_SERVICE"
	envDeployAllVersions     = "DEPLOY_ALL_VERSIONS"
	envDeployAllDataService  = "DEPLOY_ALL_DATASERVICE"
	envControlPlaneURL       = "CONTROL_PLANE_URL"
	envClusterType           = "CLUSTER_TYPE"
	envTargetClusterName     = "TARGET_CLUSTER_NAME"
	envDeployAllImages       = "DEPLOY_ALL_IMAGES"
	ImageToBeUpdated         = "IMAGE_TO_UPDATE"
	VersionToBeUpdated       = "VERSION_TO_UPDATE"
	envPDSTestAccountName    = "TEST_ACCOUNT_NAME"
	envRegisterTargetCluster = "REGISTER_TARGET_CLUSTER"
	envDeployDataService     = "DEPLOY_DATA_SERVICE"
)

var (
	tenantID                                string
	clusterID                               string
	dnsZone                                 string
	projectID                               string
	serviceType                             string
	deploymentTargetID                      string
	registrationToken                       string
	storageTemplateID                       string
	dsVersion                               string
	dsBuild                                 string
	namespace                               string
	supportedDataServices                   []string
	dataServiceDefaultResourceTemplateIDMap map[string]string
	dataServiceNameIDMap                    map[string]string
	dataServiceNameDefaultAppConfigMap      map[string]string
	deployments                             map[string][]*pds.ModelsDeployment
	err                                     error
	namespaceID                             string
	replicas                                int32
	DeployAllImages                         bool
	DeployAllDataService                    bool
	DeployAllVersions                       bool
	DataService                             string
	registerTargetCluster                   bool
	deployDataService                       bool
)

func main() {

	ControlPlaneURL := pdslib.GetAndExpectStringEnvVar(envControlPlaneURL)
	ClusterType := pdslib.GetAndExpectStringEnvVar(envClusterType)
	TargetClusterName := pdslib.GetAndExpectStringEnvVar(envTargetClusterName)
	AccountName := pdslib.GetAndExpectStringEnvVar(envPDSTestAccountName)
	DataService = pdslib.GetAndExpectStringEnvVar(envDataService)
	dsVersion = pdslib.GetAndExpectStringEnvVar(envDsVersion)
	dsBuild = pdslib.GetAndExpectStringEnvVar(envDsBuild)
	namespace = pdslib.GetAndExpectStringEnvVar(envNamespace)
	rep, err := pdslib.GetAndExpectIntEnvVar(envReplicas)
	if err != nil {
		log.Fatalf("Error while getting replicas %v", err)
	}
	replicas = int32(rep)

	registerTargetCluster, err = pdslib.GetAndExpectBoolEnvVar(envRegisterTargetCluster)
	if err != nil {
		log.Fatalf("Error while getting values to register target cluster %v", err)
	}

	deployDataService, err = pdslib.GetAndExpectBoolEnvVar(envDeployDataService)
	if err != nil {
		log.Fatalf("Error while deploying data service %v", err)
	}

	namespaceID, isavailable, err := pdslib.CheckNamespace(namespace)
	if !isavailable || err != nil {
		log.Fatalf("namespace check has failed with error %v", err)
	}

	tenantID, dnsZone, projectID, serviceType, deploymentTargetID, clusterID, registrationToken, err = pdslib.SetupPDSTest(ControlPlaneURL, ClusterType, TargetClusterName, AccountName)
	if err != nil {
		log.Fatalf("pds test setup failed with err %v", err)
	}
	log.Infof("tenantID %v dnsZone %v projectID %v, serviceType %v, deploymentTargetID %v clusterID %v", tenantID, dnsZone, projectID, serviceType, deploymentTargetID, clusterID)

	if registerTargetCluster {
		log.Info("Regsitering target cluster to control plane")
		err = pdslib.RegisterToControlPlane(ControlPlaneURL, tenantID, ClusterType, registrationToken)
		if err != nil {
			log.Fatalf("error while registering targetcluster to the control plane %v", err)
		}
	}

	if deployDataService {
		log.Info("Deploying Data Service")
		supportedDataServices = append(supportedDataServices, pdslib.GetAndExpectStringEnvVar(envDataService))
		for _, ds := range supportedDataServices {
			log.Infof("supported dataservices %v", ds)
		}

		dataServiceDefaultResourceTemplateIDMap, dataServiceNameIDMap, err = pdslib.GetResourceTemplate(tenantID, supportedDataServices)
		if err != nil {
			log.Fatalf("Error while getting resource template %v", err)
		}

		dataServiceNameDefaultAppConfigMap, err = pdslib.GetAppConfTemplate(tenantID, dataServiceNameIDMap)
		if err != nil {
			log.Fatalf("Error while getting app conf template %v", err)
		}

		storageTemplateID, err = pdslib.GetStorageTemplate(tenantID)
		if err != nil {
			log.Fatalf("Error while listing storage template %v", err)
		}

		// namespaceID, err = pdslib.GetnameSpaceID(namespace, deploymentTargetID)
		// if err != nil {
		// 	log.Fatalf("Error while getting namespace id %v", err)
		// }

		deployments, _, _, err = pdslib.DeployDataServices(dataServiceNameIDMap, projectID,
			deploymentTargetID,
			dnsZone,
			deploymentName,
			namespaceID,
			dataServiceNameDefaultAppConfigMap,
			replicas,
			serviceType,
			dataServiceDefaultResourceTemplateIDMap,
			storageTemplateID,
			DeployAllVersions,
			DeployAllImages,
			dsVersion,
			dsBuild,
		)
		if err != nil {
			log.Fatalf("Error while deploying dataservices %v", err)
		}
	}
}
