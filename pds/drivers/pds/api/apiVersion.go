// Package api comprises of all the components and associated CRUD functionality
package api

import (
	status "net/http"

	pdsutils "github.com/Madanagopal19/pds-hacktank/drivers/pds/pdsutils"
	pds "github.com/portworx/pds-api-go-client/pds/v1alpha1"
	log "github.com/sirupsen/logrus"
)

// PDSVersion struct
type PDSVersion struct {
	apiClient *pds.APIClient
}

// GetHelmChartVersion function return latest pds helm chart version.
func (v *PDSVersion) GetHelmChartVersion() (string, error) {
	versionClient := v.apiClient.APIVersionApi
	ctx, err := pdsutils.GetContext()
	if err != nil {
		log.Errorf("Error in getting context for api call: %v\n", err)
		return "", err
	}
	versionModel, res, err := versionClient.ApiVersionGet(ctx).Execute()
	if res.StatusCode != status.StatusOK {
		log.Errorf("Error when calling `ApiVersionGet``: %v\n", err)
		log.Errorf("Full HTTP response: %v\n", res)
	}
	return versionModel.GetHelmChartVersion(), err
}
