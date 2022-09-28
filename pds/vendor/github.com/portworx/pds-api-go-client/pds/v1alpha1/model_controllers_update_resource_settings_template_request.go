/*
PDS API

Portworx Data Services API Server

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package pds

import (
	"encoding/json"
)

// ControllersUpdateResourceSettingsTemplateRequest struct for ControllersUpdateResourceSettingsTemplateRequest
type ControllersUpdateResourceSettingsTemplateRequest struct {
	CpuLimit *string `json:"cpu_limit,omitempty"`
	CpuRequest *string `json:"cpu_request,omitempty"`
	MemoryLimit *string `json:"memory_limit,omitempty"`
	MemoryRequest *string `json:"memory_request,omitempty"`
	// See models.ResourceSettingsTemplate for more information.
	Name *string `json:"name,omitempty"`
	StorageRequest *string `json:"storage_request,omitempty"`
}

// NewControllersUpdateResourceSettingsTemplateRequest instantiates a new ControllersUpdateResourceSettingsTemplateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewControllersUpdateResourceSettingsTemplateRequest() *ControllersUpdateResourceSettingsTemplateRequest {
	this := ControllersUpdateResourceSettingsTemplateRequest{}
	return &this
}

// NewControllersUpdateResourceSettingsTemplateRequestWithDefaults instantiates a new ControllersUpdateResourceSettingsTemplateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewControllersUpdateResourceSettingsTemplateRequestWithDefaults() *ControllersUpdateResourceSettingsTemplateRequest {
	this := ControllersUpdateResourceSettingsTemplateRequest{}
	return &this
}

// GetCpuLimit returns the CpuLimit field value if set, zero value otherwise.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetCpuLimit() string {
	if o == nil || o.CpuLimit == nil {
		var ret string
		return ret
	}
	return *o.CpuLimit
}

// GetCpuLimitOk returns a tuple with the CpuLimit field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetCpuLimitOk() (*string, bool) {
	if o == nil || o.CpuLimit == nil {
		return nil, false
	}
	return o.CpuLimit, true
}

// HasCpuLimit returns a boolean if a field has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) HasCpuLimit() bool {
	if o != nil && o.CpuLimit != nil {
		return true
	}

	return false
}

// SetCpuLimit gets a reference to the given string and assigns it to the CpuLimit field.
func (o *ControllersUpdateResourceSettingsTemplateRequest) SetCpuLimit(v string) {
	o.CpuLimit = &v
}

// GetCpuRequest returns the CpuRequest field value if set, zero value otherwise.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetCpuRequest() string {
	if o == nil || o.CpuRequest == nil {
		var ret string
		return ret
	}
	return *o.CpuRequest
}

// GetCpuRequestOk returns a tuple with the CpuRequest field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetCpuRequestOk() (*string, bool) {
	if o == nil || o.CpuRequest == nil {
		return nil, false
	}
	return o.CpuRequest, true
}

// HasCpuRequest returns a boolean if a field has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) HasCpuRequest() bool {
	if o != nil && o.CpuRequest != nil {
		return true
	}

	return false
}

// SetCpuRequest gets a reference to the given string and assigns it to the CpuRequest field.
func (o *ControllersUpdateResourceSettingsTemplateRequest) SetCpuRequest(v string) {
	o.CpuRequest = &v
}

// GetMemoryLimit returns the MemoryLimit field value if set, zero value otherwise.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetMemoryLimit() string {
	if o == nil || o.MemoryLimit == nil {
		var ret string
		return ret
	}
	return *o.MemoryLimit
}

// GetMemoryLimitOk returns a tuple with the MemoryLimit field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetMemoryLimitOk() (*string, bool) {
	if o == nil || o.MemoryLimit == nil {
		return nil, false
	}
	return o.MemoryLimit, true
}

// HasMemoryLimit returns a boolean if a field has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) HasMemoryLimit() bool {
	if o != nil && o.MemoryLimit != nil {
		return true
	}

	return false
}

// SetMemoryLimit gets a reference to the given string and assigns it to the MemoryLimit field.
func (o *ControllersUpdateResourceSettingsTemplateRequest) SetMemoryLimit(v string) {
	o.MemoryLimit = &v
}

// GetMemoryRequest returns the MemoryRequest field value if set, zero value otherwise.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetMemoryRequest() string {
	if o == nil || o.MemoryRequest == nil {
		var ret string
		return ret
	}
	return *o.MemoryRequest
}

// GetMemoryRequestOk returns a tuple with the MemoryRequest field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetMemoryRequestOk() (*string, bool) {
	if o == nil || o.MemoryRequest == nil {
		return nil, false
	}
	return o.MemoryRequest, true
}

// HasMemoryRequest returns a boolean if a field has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) HasMemoryRequest() bool {
	if o != nil && o.MemoryRequest != nil {
		return true
	}

	return false
}

// SetMemoryRequest gets a reference to the given string and assigns it to the MemoryRequest field.
func (o *ControllersUpdateResourceSettingsTemplateRequest) SetMemoryRequest(v string) {
	o.MemoryRequest = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *ControllersUpdateResourceSettingsTemplateRequest) SetName(v string) {
	o.Name = &v
}

// GetStorageRequest returns the StorageRequest field value if set, zero value otherwise.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetStorageRequest() string {
	if o == nil || o.StorageRequest == nil {
		var ret string
		return ret
	}
	return *o.StorageRequest
}

// GetStorageRequestOk returns a tuple with the StorageRequest field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) GetStorageRequestOk() (*string, bool) {
	if o == nil || o.StorageRequest == nil {
		return nil, false
	}
	return o.StorageRequest, true
}

// HasStorageRequest returns a boolean if a field has been set.
func (o *ControllersUpdateResourceSettingsTemplateRequest) HasStorageRequest() bool {
	if o != nil && o.StorageRequest != nil {
		return true
	}

	return false
}

// SetStorageRequest gets a reference to the given string and assigns it to the StorageRequest field.
func (o *ControllersUpdateResourceSettingsTemplateRequest) SetStorageRequest(v string) {
	o.StorageRequest = &v
}

func (o ControllersUpdateResourceSettingsTemplateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.CpuLimit != nil {
		toSerialize["cpu_limit"] = o.CpuLimit
	}
	if o.CpuRequest != nil {
		toSerialize["cpu_request"] = o.CpuRequest
	}
	if o.MemoryLimit != nil {
		toSerialize["memory_limit"] = o.MemoryLimit
	}
	if o.MemoryRequest != nil {
		toSerialize["memory_request"] = o.MemoryRequest
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.StorageRequest != nil {
		toSerialize["storage_request"] = o.StorageRequest
	}
	return json.Marshal(toSerialize)
}

type NullableControllersUpdateResourceSettingsTemplateRequest struct {
	value *ControllersUpdateResourceSettingsTemplateRequest
	isSet bool
}

func (v NullableControllersUpdateResourceSettingsTemplateRequest) Get() *ControllersUpdateResourceSettingsTemplateRequest {
	return v.value
}

func (v *NullableControllersUpdateResourceSettingsTemplateRequest) Set(val *ControllersUpdateResourceSettingsTemplateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableControllersUpdateResourceSettingsTemplateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableControllersUpdateResourceSettingsTemplateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableControllersUpdateResourceSettingsTemplateRequest(val *ControllersUpdateResourceSettingsTemplateRequest) *NullableControllersUpdateResourceSettingsTemplateRequest {
	return &NullableControllersUpdateResourceSettingsTemplateRequest{value: val, isSet: true}
}

func (v NullableControllersUpdateResourceSettingsTemplateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableControllersUpdateResourceSettingsTemplateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


