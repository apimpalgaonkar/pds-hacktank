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

// ControllersPaginatedUsers struct for ControllersPaginatedUsers
type ControllersPaginatedUsers struct {
	Data []ModelsUser `json:"data,omitempty"`
	Pagination *ConstraintPagination `json:"pagination,omitempty"`
}

// NewControllersPaginatedUsers instantiates a new ControllersPaginatedUsers object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewControllersPaginatedUsers() *ControllersPaginatedUsers {
	this := ControllersPaginatedUsers{}
	return &this
}

// NewControllersPaginatedUsersWithDefaults instantiates a new ControllersPaginatedUsers object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewControllersPaginatedUsersWithDefaults() *ControllersPaginatedUsers {
	this := ControllersPaginatedUsers{}
	return &this
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *ControllersPaginatedUsers) GetData() []ModelsUser {
	if o == nil || o.Data == nil {
		var ret []ModelsUser
		return ret
	}
	return o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersPaginatedUsers) GetDataOk() ([]ModelsUser, bool) {
	if o == nil || o.Data == nil {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *ControllersPaginatedUsers) HasData() bool {
	if o != nil && o.Data != nil {
		return true
	}

	return false
}

// SetData gets a reference to the given []ModelsUser and assigns it to the Data field.
func (o *ControllersPaginatedUsers) SetData(v []ModelsUser) {
	o.Data = v
}

// GetPagination returns the Pagination field value if set, zero value otherwise.
func (o *ControllersPaginatedUsers) GetPagination() ConstraintPagination {
	if o == nil || o.Pagination == nil {
		var ret ConstraintPagination
		return ret
	}
	return *o.Pagination
}

// GetPaginationOk returns a tuple with the Pagination field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersPaginatedUsers) GetPaginationOk() (*ConstraintPagination, bool) {
	if o == nil || o.Pagination == nil {
		return nil, false
	}
	return o.Pagination, true
}

// HasPagination returns a boolean if a field has been set.
func (o *ControllersPaginatedUsers) HasPagination() bool {
	if o != nil && o.Pagination != nil {
		return true
	}

	return false
}

// SetPagination gets a reference to the given ConstraintPagination and assigns it to the Pagination field.
func (o *ControllersPaginatedUsers) SetPagination(v ConstraintPagination) {
	o.Pagination = &v
}

func (o ControllersPaginatedUsers) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Data != nil {
		toSerialize["data"] = o.Data
	}
	if o.Pagination != nil {
		toSerialize["pagination"] = o.Pagination
	}
	return json.Marshal(toSerialize)
}

type NullableControllersPaginatedUsers struct {
	value *ControllersPaginatedUsers
	isSet bool
}

func (v NullableControllersPaginatedUsers) Get() *ControllersPaginatedUsers {
	return v.value
}

func (v *NullableControllersPaginatedUsers) Set(val *ControllersPaginatedUsers) {
	v.value = val
	v.isSet = true
}

func (v NullableControllersPaginatedUsers) IsSet() bool {
	return v.isSet
}

func (v *NullableControllersPaginatedUsers) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableControllersPaginatedUsers(val *ControllersPaginatedUsers) *NullableControllersPaginatedUsers {
	return &NullableControllersPaginatedUsers{value: val, isSet: true}
}

func (v NullableControllersPaginatedUsers) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableControllersPaginatedUsers) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


