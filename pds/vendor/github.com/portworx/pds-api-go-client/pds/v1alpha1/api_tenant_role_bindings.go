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

// TenantRoleBindingsApiService TenantRoleBindingsApi service
type TenantRoleBindingsApiService service

type ApiApiTenantsIdRoleBindingsDeleteRequest struct {
	ctx context.Context
	ApiService *TenantRoleBindingsApiService
	id string
	actorType *string
}

// TenantRoleBinding actor type
func (r ApiApiTenantsIdRoleBindingsDeleteRequest) ActorType(actorType string) ApiApiTenantsIdRoleBindingsDeleteRequest {
	r.actorType = &actorType
	return r
}

func (r ApiApiTenantsIdRoleBindingsDeleteRequest) Execute() (*http.Response, error) {
	return r.ApiService.ApiTenantsIdRoleBindingsDeleteExecute(r)
}

/*
ApiTenantsIdRoleBindingsDelete Delete TenantRoleBinding

Removes a single TenantRoleBinding

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param id Tenant ID (must be valid UUID)
 @return ApiApiTenantsIdRoleBindingsDeleteRequest
*/
func (a *TenantRoleBindingsApiService) ApiTenantsIdRoleBindingsDelete(ctx context.Context, id string) ApiApiTenantsIdRoleBindingsDeleteRequest {
	return ApiApiTenantsIdRoleBindingsDeleteRequest{
		ApiService: a,
		ctx: ctx,
		id: id,
	}
}

// Execute executes the request
func (a *TenantRoleBindingsApiService) ApiTenantsIdRoleBindingsDeleteExecute(r ApiApiTenantsIdRoleBindingsDeleteRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodDelete
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "TenantRoleBindingsApiService.ApiTenantsIdRoleBindingsDelete")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/api/tenants/{id}/role-bindings"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterToString(r.id, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	// body params
	localVarPostBody = r.actorType
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
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}

type ApiApiTenantsIdRoleBindingsGetRequest struct {
	ctx context.Context
	ApiService *TenantRoleBindingsApiService
	id string
	sortBy *string
	roleName *string
	actorId *string
	actorType *string
}

// A given TenantRoleBinding attribute to sort results by (one of: role_name, actor_id)
func (r ApiApiTenantsIdRoleBindingsGetRequest) SortBy(sortBy string) ApiApiTenantsIdRoleBindingsGetRequest {
	r.sortBy = &sortBy
	return r
}
// Filter results by TenantRoleBinding assigned role name
func (r ApiApiTenantsIdRoleBindingsGetRequest) RoleName(roleName string) ApiApiTenantsIdRoleBindingsGetRequest {
	r.roleName = &roleName
	return r
}
// Filter results by TenantRoleBinding actor id
func (r ApiApiTenantsIdRoleBindingsGetRequest) ActorId(actorId string) ApiApiTenantsIdRoleBindingsGetRequest {
	r.actorId = &actorId
	return r
}
// Filter results by TenantRoleBinding actor type
func (r ApiApiTenantsIdRoleBindingsGetRequest) ActorType(actorType string) ApiApiTenantsIdRoleBindingsGetRequest {
	r.actorType = &actorType
	return r
}

func (r ApiApiTenantsIdRoleBindingsGetRequest) Execute() (*ControllersPaginatedTenantRoleBindings, *http.Response, error) {
	return r.ApiService.ApiTenantsIdRoleBindingsGetExecute(r)
}

/*
ApiTenantsIdRoleBindingsGet List TenantRoleBindings

Lists TenantRoleBindings

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param id Tenant ID (must be valid UUID)
 @return ApiApiTenantsIdRoleBindingsGetRequest
*/
func (a *TenantRoleBindingsApiService) ApiTenantsIdRoleBindingsGet(ctx context.Context, id string) ApiApiTenantsIdRoleBindingsGetRequest {
	return ApiApiTenantsIdRoleBindingsGetRequest{
		ApiService: a,
		ctx: ctx,
		id: id,
	}
}

// Execute executes the request
//  @return ControllersPaginatedTenantRoleBindings
func (a *TenantRoleBindingsApiService) ApiTenantsIdRoleBindingsGetExecute(r ApiApiTenantsIdRoleBindingsGetRequest) (*ControllersPaginatedTenantRoleBindings, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ControllersPaginatedTenantRoleBindings
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "TenantRoleBindingsApiService.ApiTenantsIdRoleBindingsGet")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/api/tenants/{id}/role-bindings"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterToString(r.id, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.sortBy != nil {
		localVarQueryParams.Add("sort_by", parameterToString(*r.sortBy, ""))
	}
	if r.roleName != nil {
		localVarQueryParams.Add("role_name", parameterToString(*r.roleName, ""))
	}
	if r.actorId != nil {
		localVarQueryParams.Add("actor_id", parameterToString(*r.actorId, ""))
	}
	if r.actorType != nil {
		localVarQueryParams.Add("actor_type", parameterToString(*r.actorType, ""))
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

type ApiApiTenantsIdRoleBindingsPutRequest struct {
	ctx context.Context
	ApiService *TenantRoleBindingsApiService
	id string
	body *ControllersUpsertTenantRoleBindingRequest
}

// Request body containing the tenant role binding
func (r ApiApiTenantsIdRoleBindingsPutRequest) Body(body ControllersUpsertTenantRoleBindingRequest) ApiApiTenantsIdRoleBindingsPutRequest {
	r.body = &body
	return r
}

func (r ApiApiTenantsIdRoleBindingsPutRequest) Execute() (*ModelsTenantRoleBinding, *http.Response, error) {
	return r.ApiService.ApiTenantsIdRoleBindingsPutExecute(r)
}

/*
ApiTenantsIdRoleBindingsPut Create TenantRoleBinding

Creates a new TenantRoleBinding

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param id Tenant ID (must be valid UUID)
 @return ApiApiTenantsIdRoleBindingsPutRequest
*/
func (a *TenantRoleBindingsApiService) ApiTenantsIdRoleBindingsPut(ctx context.Context, id string) ApiApiTenantsIdRoleBindingsPutRequest {
	return ApiApiTenantsIdRoleBindingsPutRequest{
		ApiService: a,
		ctx: ctx,
		id: id,
	}
}

// Execute executes the request
//  @return ModelsTenantRoleBinding
func (a *TenantRoleBindingsApiService) ApiTenantsIdRoleBindingsPutExecute(r ApiApiTenantsIdRoleBindingsPutRequest) (*ModelsTenantRoleBinding, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPut
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ModelsTenantRoleBinding
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "TenantRoleBindingsApiService.ApiTenantsIdRoleBindingsPut")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/api/tenants/{id}/role-bindings"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterToString(r.id, "")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.body == nil {
		return localVarReturnValue, nil, reportError("body is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

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
	// body params
	localVarPostBody = r.body
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
