// Package api comprises of all the components and associated CRUD functionality
package api

import (
	status "net/http"

	pdsutils "github.com/Madanagopal19/pds-hacktank/drivers/pds/pdsutils"
	pds "github.com/portworx/pds-api-go-client/pds/v1alpha1"
	log "github.com/sirupsen/logrus"
)

// Version struct
type Version struct {
	apiClient *pds.APIClient
}

// ListDataServiceVersions return pds versions models.
func (v *Version) ListDataServiceVersions(dataServiceID string) ([]pds.ModelsVersion, error) {
	versionClient := v.apiClient.VersionsApi
	ctx, err := pdsutils.GetContext()
	if err != nil {
		log.Errorf("Error in getting context for api call: %v\n", err)
		return nil, err
	}
	versionModels, res, err := versionClient.ApiDataServicesIdVersionsGet(ctx, dataServiceID).Execute()
	if res.StatusCode != status.StatusOK {
		log.Errorf("Error when calling `ApiDataServicesIdVersionsGet``: %v\n", err)
		log.Errorf("Full HTTP response: %v\n", res)
	}
	return versionModels.GetData(), err
}

// GetVersion return pds version model.
func (v *Version) GetVersion(versionID string) (*pds.ModelsVersion, error) {
	versionClient := v.apiClient.VersionsApi
	ctx, err := pdsutils.GetContext()
	if err != nil {
		log.Errorf("Error in getting context for api call: %v\n", err)
		return nil, err
	}
	versionModel, res, err := versionClient.ApiVersionsIdGet(ctx, versionID).Execute()
	if res.StatusCode != status.StatusOK {
		log.Errorf("Error when calling `ApiVersionsIdGet``: %v\n", err)
		log.Errorf("Full HTTP response: %v\n", res)
	}
	return versionModel, err
}
