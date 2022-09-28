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

// ModelsGlobalRoleBinding struct for ModelsGlobalRoleBinding
type ModelsGlobalRoleBinding struct {
	ActorId *string `json:"actor_id,omitempty"`
	ActorType *string `json:"actor_type,omitempty"`
	RoleName *string `json:"role_name,omitempty"`
}

// NewModelsGlobalRoleBinding instantiates a new ModelsGlobalRoleBinding object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewModelsGlobalRoleBinding() *ModelsGlobalRoleBinding {
	this := ModelsGlobalRoleBinding{}
	return &this
}

// NewModelsGlobalRoleBindingWithDefaults instantiates a new ModelsGlobalRoleBinding object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewModelsGlobalRoleBindingWithDefaults() *ModelsGlobalRoleBinding {
	this := ModelsGlobalRoleBinding{}
	return &this
}

// GetActorId returns the ActorId field value if set, zero value otherwise.
func (o *ModelsGlobalRoleBinding) GetActorId() string {
	if o == nil || o.ActorId == nil {
		var ret string
		return ret
	}
	return *o.ActorId
}

// GetActorIdOk returns a tuple with the ActorId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsGlobalRoleBinding) GetActorIdOk() (*string, bool) {
	if o == nil || o.ActorId == nil {
		return nil, false
	}
	return o.ActorId, true
}

// HasActorId returns a boolean if a field has been set.
func (o *ModelsGlobalRoleBinding) HasActorId() bool {
	if o != nil && o.ActorId != nil {
		return true
	}

	return false
}

// SetActorId gets a reference to the given string and assigns it to the ActorId field.
func (o *ModelsGlobalRoleBinding) SetActorId(v string) {
	o.ActorId = &v
}

// GetActorType returns the ActorType field value if set, zero value otherwise.
func (o *ModelsGlobalRoleBinding) GetActorType() string {
	if o == nil || o.ActorType == nil {
		var ret string
		return ret
	}
	return *o.ActorType
}

// GetActorTypeOk returns a tuple with the ActorType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsGlobalRoleBinding) GetActorTypeOk() (*string, bool) {
	if o == nil || o.ActorType == nil {
		return nil, false
	}
	return o.ActorType, true
}

// HasActorType returns a boolean if a field has been set.
func (o *ModelsGlobalRoleBinding) HasActorType() bool {
	if o != nil && o.ActorType != nil {
		return true
	}

	return false
}

// SetActorType gets a reference to the given string and assigns it to the ActorType field.
func (o *ModelsGlobalRoleBinding) SetActorType(v string) {
	o.ActorType = &v
}

// GetRoleName returns the RoleName field value if set, zero value otherwise.
func (o *ModelsGlobalRoleBinding) GetRoleName() string {
	if o == nil || o.RoleName == nil {
		var ret string
		return ret
	}
	return *o.RoleName
}

// GetRoleNameOk returns a tuple with the RoleName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsGlobalRoleBinding) GetRoleNameOk() (*string, bool) {
	if o == nil || o.RoleName == nil {
		return nil, false
	}
	return o.RoleName, true
}

// HasRoleName returns a boolean if a field has been set.
func (o *ModelsGlobalRoleBinding) HasRoleName() bool {
	if o != nil && o.RoleName != nil {
		return true
	}

	return false
}

// SetRoleName gets a reference to the given string and assigns it to the RoleName field.
func (o *ModelsGlobalRoleBinding) SetRoleName(v string) {
	o.RoleName = &v
}

func (o ModelsGlobalRoleBinding) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.ActorId != nil {
		toSerialize["actor_id"] = o.ActorId
	}
	if o.ActorType != nil {
		toSerialize["actor_type"] = o.ActorType
	}
	if o.RoleName != nil {
		toSerialize["role_name"] = o.RoleName
	}
	return json.Marshal(toSerialize)
}

type NullableModelsGlobalRoleBinding struct {
	value *ModelsGlobalRoleBinding
	isSet bool
}

func (v NullableModelsGlobalRoleBinding) Get() *ModelsGlobalRoleBinding {
	return v.value
}

func (v *NullableModelsGlobalRoleBinding) Set(val *ModelsGlobalRoleBinding) {
	v.value = val
	v.isSet = true
}

func (v NullableModelsGlobalRoleBinding) IsSet() bool {
	return v.isSet
}

func (v *NullableModelsGlobalRoleBinding) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableModelsGlobalRoleBinding(val *ModelsGlobalRoleBinding) *NullableModelsGlobalRoleBinding {
	return &NullableModelsGlobalRoleBinding{value: val, isSet: true}
}

func (v NullableModelsGlobalRoleBinding) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableModelsGlobalRoleBinding) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

