/*
PDS API

Portworx Data Services API Server

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package pds

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Linger please
var (
	_ context.Context
)

// DataServicesApiService DataServicesApi service
type DataServicesApiService service

type ApiApiDataServicesGetRequest struct {
	ctx context.Context
	ApiService *DataServicesApiService
	sortBy *string
	limit *string
	continuation *string
	id *string
	name *string
	shortName *string
	hasIncrementalBackup *bool
	hasFullBackup *bool
	comingSoon *bool
}

// A given Data Service attribute to sort results by (one of: id, name, short_name, created_at)
func (r ApiApiDataServicesGetRequest) SortBy(sortBy string) ApiApiDataServicesGetRequest {
	r.sortBy = &sortBy
	return r
}
// Maximum number of rows to return (could be less)
func (r ApiApiDataServicesGetRequest) Limit(limit string) ApiApiDataServicesGetRequest {
	r.limit = &limit
	return r
}
// Use a token returned by a previous query to continue listing with the next batch of rows
func (r ApiApiDataServicesGetRequest) Continuation(continuation string) ApiApiDataServicesGetRequest {
	r.continuation = &continuation
	return r
}
// Filter results by Data Service ID
func (r ApiApiDataServicesGetRequest) Id(id string) ApiApiDataServicesGetRequest {
	r.id = &id
	return r
}
// Filter results by Data Service name
func (r ApiApiDataServicesGetRequest) Name(name string) ApiApiDataServicesGetRequest {
	r.name = &name
	return r
}
// Filter results by Data Service short name
func (r ApiApiDataServicesGetRequest) ShortName(shortName string) ApiApiDataServicesGetRequest {
	r.shortName = &shortName
	return r
}
// Filter results based on incremental backup eligibility
func (r ApiApiDataServicesGetRequest) HasIncrementalBackup(hasIncrementalBackup bool) ApiApiDataServicesGetRequest {
	r.hasIncrementalBackup = &hasIncrementalBackup
	return r
}
// Filter results based on vault full backup eligibility
func (r ApiApiDataServicesGetRequest) HasFullBackup(hasFullBackup bool) ApiApiDataServicesGetRequest {
	r.hasFullBackup = &hasFullBackup
	return r
}
// Filter results based on &#39;Coming soon&#39; flag
func (r ApiApiDataServicesGetRequest) ComingSoon(comingSoon bool) ApiApiDataServicesGetRequest {
	r.comingSoon = &comingSoon
	return r
}

func (r ApiApiDataServicesGetRequest) Execute() (*ControllersPaginatedDataServices, *http.Response, error) {
	return r.ApiService.ApiDataServicesGetExecute(r)
}

/*
ApiDataServicesGet List Data Services

Lists Data Services

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiApiDataServicesGetRequest
*/
func (a *DataServicesApiService) ApiDataServicesGet(ctx context.Context) ApiApiDataServicesGetRequest {
	return ApiApiDataServicesGetRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return ControllersPaginatedDataServices
func (a *DataServicesApiService) ApiDataServicesGetExecute(r ApiApiDataServicesGetRequest) (*ControllersPaginatedDataServices, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ControllersPaginatedDataServices
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "DataServicesApiService.ApiDataServicesGet")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/api/data-services"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.sortBy != nil {
		localVarQueryParams.Add("sort_by", parameterToString(*r.sortBy, ""))
	}
	if r.limit != nil {
		localVarQueryParams.Add("limit", parameterToString(*r.limit, ""))
	}
	if r.continuation != nil {
		localVarQueryParams.Add("continuation", parameterToString(*r.continuation, ""))
	}
	if r.id != nil {
		localVarQueryParams.Add("id", parameterToString(*r.id, ""))
	}
	if r.name != nil {
		localVarQueryParams.Add("name", parameterToString(*r.name, ""))
	}
	if r.shortName != nil {
		localVarQueryParams.Add("short_name", parameterToString(*r.shortName, ""))
	}
	if r.hasIncrementalBackup != nil {
		localVarQueryParams.Add("has_incremental_backup", parameterToString(*r.hasIncrementalBackup, ""))
	}
	if r.hasFullBackup != nil {
		localVarQueryParams.Add("has_full_backup", parameterToString(*r.hasFullBackup, ""))
	}
	if r.comingSoon != nil {
		localVarQueryParams.Add("coming_soon", parameterToString(*r.comingSoon, ""))
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.ctx != nil {
		// API Key Authentication
		if auth, ok := r.ctx.Value(ContextAPIKeys).(map[string]APIKey); ok {
			if apiKey, ok := auth["ApiKeyAuth"]; ok {
				var key string
				if apiKey.Prefix != "" {
					key = apiKey.Prefix + " " + apiKey.Key
				} else {
					key = apiKey.Key
				}
				localVarHeaderParams["Authorization"] = key
			}
		}
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiApiDataServicesIdGetRequest struct {
	ctx context.Context
	ApiService *DataServicesApiService
	id string
}


func (r ApiApiDataServicesIdGetRequest) Execute() (*ModelsDataService, *http.Response, error) {
	return r.ApiService.ApiDataServicesIdGetExecute(r)
}

/*
ApiDataServicesIdGet Get Data Service

Fetches a single Data Service

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param id Data Service ID (must be a valid UUID)
 @return ApiApiDataServicesIdGetRequest
*/
func (a *DataServicesApiService) ApiDataServicesIdGet(ctx context.Context, id string) ApiApiDataServicesIdGetRequest {
	return ApiApiDataServicesIdGetRequest{
		ApiService: a,
		ctx: ctx,
		id: id,
	}
}

// Execute executes the request
//  @return ModelsDataService
func (a *DataServicesApiService) ApiDataServicesIdGetExecute(r ApiApiDataServicesIdGetRequest) (*ModelsDataService, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ModelsDataService
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "DataServicesApiService.ApiDataServicesIdGet")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/api/data-services/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterToString(r.id, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.ctx != nil {
		// API Key Authentication
		if auth, ok := r.ctx.Value(ContextAPIKeys).(map[string]APIKey); ok {
			if apiKey, ok := auth["ApiKeyAuth"]; ok {
				var key string
				if apiKey.Prefix != "" {
					key = apiKey.Prefix + " " + apiKey.Key
				} else {
					key = apiKey.Key
				}
				localVarHeaderParams["Authorization"] = key
			}
		}
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}
