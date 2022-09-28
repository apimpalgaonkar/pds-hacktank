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

// ControllersPartialCredentials struct for ControllersPartialCredentials
type ControllersPartialCredentials struct {
	Azure *ControllersPartialAzureCredentials `json:"azure,omitempty"`
	Google *ControllersPartialGoogleCredentials `json:"google,omitempty"`
	S3 *ControllersPartialS3Credentials `json:"s3,omitempty"`
	S3Compatible *ControllersPartialS3CompatibleCredentials `json:"s3_compatible,omitempty"`
}

// NewControllersPartialCredentials instantiates a new ControllersPartialCredentials object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewControllersPartialCredentials() *ControllersPartialCredentials {
	this := ControllersPartialCredentials{}
	return &this
}

// NewControllersPartialCredentialsWithDefaults instantiates a new ControllersPartialCredentials object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewControllersPartialCredentialsWithDefaults() *ControllersPartialCredentials {
	this := ControllersPartialCredentials{}
	return &this
}

// GetAzure returns the Azure field value if set, zero value otherwise.
func (o *ControllersPartialCredentials) GetAzure() ControllersPartialAzureCredentials {
	if o == nil || o.Azure == nil {
		var ret ControllersPartialAzureCredentials
		return ret
	}
	return *o.Azure
}

// GetAzureOk returns a tuple with the Azure field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersPartialCredentials) GetAzureOk() (*ControllersPartialAzureCredentials, bool) {
	if o == nil || o.Azure == nil {
		return nil, false
	}
	return o.Azure, true
}

// HasAzure returns a boolean if a field has been set.
func (o *ControllersPartialCredentials) HasAzure() bool {
	if o != nil && o.Azure != nil {
		return true
	}

	return false
}

// SetAzure gets a reference to the given ControllersPartialAzureCredentials and assigns it to the Azure field.
func (o *ControllersPartialCredentials) SetAzure(v ControllersPartialAzureCredentials) {
	o.Azure = &v
}

// GetGoogle returns the Google field value if set, zero value otherwise.
func (o *ControllersPartialCredentials) GetGoogle() ControllersPartialGoogleCredentials {
	if o == nil || o.Google == nil {
		var ret ControllersPartialGoogleCredentials
		return ret
	}
	return *o.Google
}

// GetGoogleOk returns a tuple with the Google field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersPartialCredentials) GetGoogleOk() (*ControllersPartialGoogleCredentials, bool) {
	if o == nil || o.Google == nil {
		return nil, false
	}
	return o.Google, true
}

// HasGoogle returns a boolean if a field has been set.
func (o *ControllersPartialCredentials) HasGoogle() bool {
	if o != nil && o.Google != nil {
		return true
	}

	return false
}

// SetGoogle gets a reference to the given ControllersPartialGoogleCredentials and assigns it to the Google field.
func (o *ControllersPartialCredentials) SetGoogle(v ControllersPartialGoogleCredentials) {
	o.Google = &v
}

// GetS3 returns the S3 field value if set, zero value otherwise.
func (o *ControllersPartialCredentials) GetS3() ControllersPartialS3Credentials {
	if o == nil || o.S3 == nil {
		var ret ControllersPartialS3Credentials
		return ret
	}
	return *o.S3
}

// GetS3Ok returns a tuple with the S3 field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersPartialCredentials) GetS3Ok() (*ControllersPartialS3Credentials, bool) {
	if o == nil || o.S3 == nil {
		return nil, false
	}
	return o.S3, true
}

// HasS3 returns a boolean if a field has been set.
func (o *ControllersPartialCredentials) HasS3() bool {
	if o != nil && o.S3 != nil {
		return true
	}

	return false
}

// SetS3 gets a reference to the given ControllersPartialS3Credentials and assigns it to the S3 field.
func (o *ControllersPartialCredentials) SetS3(v ControllersPartialS3Credentials) {
	o.S3 = &v
}

// GetS3Compatible returns the S3Compatible field value if set, zero value otherwise.
func (o *ControllersPartialCredentials) GetS3Compatible() ControllersPartialS3CompatibleCredentials {
	if o == nil || o.S3Compatible == nil {
		var ret ControllersPartialS3CompatibleCredentials
		return ret
	}
	return *o.S3Compatible
}

// GetS3CompatibleOk returns a tuple with the S3Compatible field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ControllersPartialCredentials) GetS3CompatibleOk() (*ControllersPartialS3CompatibleCredentials, bool) {
	if o == nil || o.S3Compatible == nil {
		return nil, false
	}
	return o.S3Compatible, true
}

// HasS3Compatible returns a boolean if a field has been set.
func (o *ControllersPartialCredentials) HasS3Compatible() bool {
	if o != nil && o.S3Compatible != nil {
		return true
	}

	return false
}

// SetS3Compatible gets a reference to the given ControllersPartialS3CompatibleCredentials and assigns it to the S3Compatible field.
func (o *ControllersPartialCredentials) SetS3Compatible(v ControllersPartialS3CompatibleCredentials) {
	o.S3Compatible = &v
}

func (o ControllersPartialCredentials) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Azure != nil {
		toSerialize["azure"] = o.Azure
	}
	if o.Google != nil {
		toSerialize["google"] = o.Google
	}
	if o.S3 != nil {
		toSerialize["s3"] = o.S3
	}
	if o.S3Compatible != nil {
		toSerialize["s3_compatible"] = o.S3Compatible
	}
	return json.Marshal(toSerialize)
}

type NullableControllersPartialCredentials struct {
	value *ControllersPartialCredentials
	isSet bool
}

func (v NullableControllersPartialCredentials) Get() *ControllersPartialCredentials {
	return v.value
}

func (v *NullableControllersPartialCredentials) Set(val *ControllersPartialCredentials) {
	v.value = val
	v.isSet = true
}

func (v NullableControllersPartialCredentials) IsSet() bool {
	return v.isSet
}

func (v *NullableControllersPartialCredentials) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableControllersPartialCredentials(val *ControllersPartialCredentials) *NullableControllersPartialCredentials {
	return &NullableControllersPartialCredentials{value: val, isSet: true}
}

func (v NullableControllersPartialCredentials) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableControllersPartialCredentials) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


