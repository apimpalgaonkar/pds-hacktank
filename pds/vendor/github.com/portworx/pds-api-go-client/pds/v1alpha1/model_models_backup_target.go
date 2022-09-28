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

// ModelsBackupTarget struct for ModelsBackupTarget
type ModelsBackupTarget struct {
	AccountId *string `json:"account_id,omitempty"`
	BackupCredentialsId *string `json:"backup_credentials_id,omitempty"`
	// Bucket name for S3 or S3 compatible. Container name for Azure.
	Bucket *string `json:"bucket,omitempty"`
	// CreatedAt is autogenerated on creation
	CreatedAt *string `json:"created_at,omitempty"`
	// ID is auto generated on creation
	Id *string `json:"id,omitempty"`
	// Name of the backup target. Must be unique for the given tenant.
	Name *string `json:"name,omitempty"`
	// Region of the bucket. Required for S3. Otherwise must be empty.
	Region *string `json:"region,omitempty"`
	TenantId *string `json:"tenant_id,omitempty"`
	// Type of the backup target. Must match the used backup credentials.
	Type *string `json:"type,omitempty"`
	// UpdatedAt is autogenerated on update
	UpdatedAt *string `json:"updated_at,omitempty"`
}

// NewModelsBackupTarget instantiates a new ModelsBackupTarget object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewModelsBackupTarget() *ModelsBackupTarget {
	this := ModelsBackupTarget{}
	return &this
}

// NewModelsBackupTargetWithDefaults instantiates a new ModelsBackupTarget object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewModelsBackupTargetWithDefaults() *ModelsBackupTarget {
	this := ModelsBackupTarget{}
	return &this
}

// GetAccountId returns the AccountId field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetAccountId() string {
	if o == nil || o.AccountId == nil {
		var ret string
		return ret
	}
	return *o.AccountId
}

// GetAccountIdOk returns a tuple with the AccountId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetAccountIdOk() (*string, bool) {
	if o == nil || o.AccountId == nil {
		return nil, false
	}
	return o.AccountId, true
}

// HasAccountId returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasAccountId() bool {
	if o != nil && o.AccountId != nil {
		return true
	}

	return false
}

// SetAccountId gets a reference to the given string and assigns it to the AccountId field.
func (o *ModelsBackupTarget) SetAccountId(v string) {
	o.AccountId = &v
}

// GetBackupCredentialsId returns the BackupCredentialsId field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetBackupCredentialsId() string {
	if o == nil || o.BackupCredentialsId == nil {
		var ret string
		return ret
	}
	return *o.BackupCredentialsId
}

// GetBackupCredentialsIdOk returns a tuple with the BackupCredentialsId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetBackupCredentialsIdOk() (*string, bool) {
	if o == nil || o.BackupCredentialsId == nil {
		return nil, false
	}
	return o.BackupCredentialsId, true
}

// HasBackupCredentialsId returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasBackupCredentialsId() bool {
	if o != nil && o.BackupCredentialsId != nil {
		return true
	}

	return false
}

// SetBackupCredentialsId gets a reference to the given string and assigns it to the BackupCredentialsId field.
func (o *ModelsBackupTarget) SetBackupCredentialsId(v string) {
	o.BackupCredentialsId = &v
}

// GetBucket returns the Bucket field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetBucket() string {
	if o == nil || o.Bucket == nil {
		var ret string
		return ret
	}
	return *o.Bucket
}

// GetBucketOk returns a tuple with the Bucket field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetBucketOk() (*string, bool) {
	if o == nil || o.Bucket == nil {
		return nil, false
	}
	return o.Bucket, true
}

// HasBucket returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasBucket() bool {
	if o != nil && o.Bucket != nil {
		return true
	}

	return false
}

// SetBucket gets a reference to the given string and assigns it to the Bucket field.
func (o *ModelsBackupTarget) SetBucket(v string) {
	o.Bucket = &v
}

// GetCreatedAt returns the CreatedAt field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetCreatedAt() string {
	if o == nil || o.CreatedAt == nil {
		var ret string
		return ret
	}
	return *o.CreatedAt
}

// GetCreatedAtOk returns a tuple with the CreatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetCreatedAtOk() (*string, bool) {
	if o == nil || o.CreatedAt == nil {
		return nil, false
	}
	return o.CreatedAt, true
}

// HasCreatedAt returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasCreatedAt() bool {
	if o != nil && o.CreatedAt != nil {
		return true
	}

	return false
}

// SetCreatedAt gets a reference to the given string and assigns it to the CreatedAt field.
func (o *ModelsBackupTarget) SetCreatedAt(v string) {
	o.CreatedAt = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *ModelsBackupTarget) SetId(v string) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *ModelsBackupTarget) SetName(v string) {
	o.Name = &v
}

// GetRegion returns the Region field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetRegion() string {
	if o == nil || o.Region == nil {
		var ret string
		return ret
	}
	return *o.Region
}

// GetRegionOk returns a tuple with the Region field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetRegionOk() (*string, bool) {
	if o == nil || o.Region == nil {
		return nil, false
	}
	return o.Region, true
}

// HasRegion returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasRegion() bool {
	if o != nil && o.Region != nil {
		return true
	}

	return false
}

// SetRegion gets a reference to the given string and assigns it to the Region field.
func (o *ModelsBackupTarget) SetRegion(v string) {
	o.Region = &v
}

// GetTenantId returns the TenantId field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetTenantId() string {
	if o == nil || o.TenantId == nil {
		var ret string
		return ret
	}
	return *o.TenantId
}

// GetTenantIdOk returns a tuple with the TenantId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetTenantIdOk() (*string, bool) {
	if o == nil || o.TenantId == nil {
		return nil, false
	}
	return o.TenantId, true
}

// HasTenantId returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasTenantId() bool {
	if o != nil && o.TenantId != nil {
		return true
	}

	return false
}

// SetTenantId gets a reference to the given string and assigns it to the TenantId field.
func (o *ModelsBackupTarget) SetTenantId(v string) {
	o.TenantId = &v
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetType() string {
	if o == nil || o.Type == nil {
		var ret string
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetTypeOk() (*string, bool) {
	if o == nil || o.Type == nil {
		return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasType() bool {
	if o != nil && o.Type != nil {
		return true
	}

	return false
}

// SetType gets a reference to the given string and assigns it to the Type field.
func (o *ModelsBackupTarget) SetType(v string) {
	o.Type = &v
}

// GetUpdatedAt returns the UpdatedAt field value if set, zero value otherwise.
func (o *ModelsBackupTarget) GetUpdatedAt() string {
	if o == nil || o.UpdatedAt == nil {
		var ret string
		return ret
	}
	return *o.UpdatedAt
}

// GetUpdatedAtOk returns a tuple with the UpdatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackupTarget) GetUpdatedAtOk() (*string, bool) {
	if o == nil || o.UpdatedAt == nil {
		return nil, false
	}
	return o.UpdatedAt, true
}

// HasUpdatedAt returns a boolean if a field has been set.
func (o *ModelsBackupTarget) HasUpdatedAt() bool {
	if o != nil && o.UpdatedAt != nil {
		return true
	}

	return false
}

// SetUpdatedAt gets a reference to the given string and assigns it to the UpdatedAt field.
func (o *ModelsBackupTarget) SetUpdatedAt(v string) {
	o.UpdatedAt = &v
}

func (o ModelsBackupTarget) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.AccountId != nil {
		toSerialize["account_id"] = o.AccountId
	}
	if o.BackupCredentialsId != nil {
		toSerialize["backup_credentials_id"] = o.BackupCredentialsId
	}
	if o.Bucket != nil {
		toSerialize["bucket"] = o.Bucket
	}
	if o.CreatedAt != nil {
		toSerialize["created_at"] = o.CreatedAt
	}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.Region != nil {
		toSerialize["region"] = o.Region
	}
	if o.TenantId != nil {
		toSerialize["tenant_id"] = o.TenantId
	}
	if o.Type != nil {
		toSerialize["type"] = o.Type
	}
	if o.UpdatedAt != nil {
		toSerialize["updated_at"] = o.UpdatedAt
	}
	return json.Marshal(toSerialize)
}

type NullableModelsBackupTarget struct {
	value *ModelsBackupTarget
	isSet bool
}

func (v NullableModelsBackupTarget) Get() *ModelsBackupTarget {
	return v.value
}

func (v *NullableModelsBackupTarget) Set(val *ModelsBackupTarget) {
	v.value = val
	v.isSet = true
}

func (v NullableModelsBackupTarget) IsSet() bool {
	return v.isSet
}

func (v *NullableModelsBackupTarget) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableModelsBackupTarget(val *ModelsBackupTarget) *NullableModelsBackupTarget {
	return &NullableModelsBackupTarget{value: val, isSet: true}
}

func (v NullableModelsBackupTarget) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableModelsBackupTarget) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


