package api

import (
	status "net/http"

	pdsutils "github.com/Madanagopal19/pds-hacktank/drivers/pds/pdsutils"
	pds "github.com/portworx/pds-api-go-client/pds/v1alpha1"
	log "github.com/sirupsen/logrus"
)

// Image struct
type Image struct {
	apiClient *pds.APIClient
}

// ListImages return images models for given version.
func (img *Image) ListImages(versionID string) ([]pds.ModelsImage, error) {
	imgClient := img.apiClient.ImagesApi
	ctx, err := pdsutils.GetContext()
	if err != nil {
		log.Errorf("Error in getting context for api call: %v\n", err)
		return nil, err
	}
	imgModels, res, err := imgClient.ApiVersionsIdImagesGet(ctx, versionID).Execute()

	if res.StatusCode != status.StatusOK {
		log.Errorf("Error when calling `ApiVersionsIdImagesGet``: %v\n", err)
		log.Errorf("Full HTTP response: %v\n", res)
	}
	return imgModels.GetData(), err
}

// GetImage return image model.
func (img *Image) GetImage(imageID string) (*pds.ModelsImage, error) {
	imgClient := img.apiClient.ImagesApi
	ctx, err := pdsutils.GetContext()
	if err != nil {
		log.Errorf("Error in getting context for api call: %v\n", err)
		return nil, err
	}
	imgModel, res, err := imgClient.ApiImagesIdGet(ctx, imageID).Execute()

	if res.StatusCode != status.StatusOK {
		log.Errorf("Error when calling `ApiImagesIdGet``: %v\n", err)
		log.Errorf("Full HTTP response: %v\n", res)
	}
	return imgModel, err
}
