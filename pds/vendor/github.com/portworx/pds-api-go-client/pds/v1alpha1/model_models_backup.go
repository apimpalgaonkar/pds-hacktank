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

// ModelsBackup struct for ModelsBackup
type ModelsBackup struct {
	AccountId *string `json:"account_id,omitempty"`
	BackupLevel *string `json:"backup_level,omitempty"`
	BackupTargetId *string `json:"backup_target_id,omitempty"`
	BackupType *string `json:"backup_type,omitempty"`
	// ClusterResourceName k8s resource name for backup, built from ID.
	ClusterResourceName *string `json:"cluster_resource_name,omitempty"`
	// CreatedAt is autogenerated on creation
	CreatedAt *string `json:"created_at,omitempty"`
	DataServiceId *string `json:"data_service_id,omitempty"`
	DeploymentId *string `json:"deployment_id,omitempty"`
	// DeploymentName name of the deployment to give the user more info in cases when the deployment has already been deleted.
	DeploymentName *string `json:"deployment_name,omitempty"`
	// DeploymentTargetID on which target the backup is created (models.DeploymentTarget).
	DeploymentTargetId *string `json:"deployment_target_id,omitempty"`
	// ID is auto generated on creation
	Id *string `json:"id,omitempty"`
	// JobHistoryLimit is a number of retained backup jobs. Must be 1 or greater.
	JobHistoryLimit *int32 `json:"job_history_limit,omitempty"`
	// NamespaceID in which namespace the Backup CR is created (models.Namespace).
	NamespaceId *string `json:"namespace_id,omitempty"`
	ProjectId *string `json:"project_id,omitempty"`
	// ReclaimPolicy decides if the volume snapshots should get deleted when a Backup CR gets deleted.
	ReclaimPolicy *string `json:"reclaim_policy,omitempty"`
	// Schedule holds a CRON expression for the backup schedule.
	Schedule *string `json:"schedule,omitempty"`
	// State of backup CR in target cluster.
	State *string `json:"state,omitempty"`
	// Suspend allows us to suspend a scheduled backup from creating new backup jobs.
	Suspend *bool `json:"suspend,omitempty"`
	TenantId *string `json:"tenant_id,omitempty"`
	// UpdatedAt is autogenerated on update
	UpdatedAt *string `json:"updated_at,omitempty"`
}

// NewModelsBackup instantiates a new ModelsBackup object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewModelsBackup() *ModelsBackup {
	this := ModelsBackup{}
	return &this
}

// NewModelsBackupWithDefaults instantiates a new ModelsBackup object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewModelsBackupWithDefaults() *ModelsBackup {
	this := ModelsBackup{}
	return &this
}

// GetAccountId returns the AccountId field value if set, zero value otherwise.
func (o *ModelsBackup) GetAccountId() string {
	if o == nil || o.AccountId == nil {
		var ret string
		return ret
	}
	return *o.AccountId
}

// GetAccountIdOk returns a tuple with the AccountId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetAccountIdOk() (*string, bool) {
	if o == nil || o.AccountId == nil {
		return nil, false
	}
	return o.AccountId, true
}

// HasAccountId returns a boolean if a field has been set.
func (o *ModelsBackup) HasAccountId() bool {
	if o != nil && o.AccountId != nil {
		return true
	}

	return false
}

// SetAccountId gets a reference to the given string and assigns it to the AccountId field.
func (o *ModelsBackup) SetAccountId(v string) {
	o.AccountId = &v
}

// GetBackupLevel returns the BackupLevel field value if set, zero value otherwise.
func (o *ModelsBackup) GetBackupLevel() string {
	if o == nil || o.BackupLevel == nil {
		var ret string
		return ret
	}
	return *o.BackupLevel
}

// GetBackupLevelOk returns a tuple with the BackupLevel field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetBackupLevelOk() (*string, bool) {
	if o == nil || o.BackupLevel == nil {
		return nil, false
	}
	return o.BackupLevel, true
}

// HasBackupLevel returns a boolean if a field has been set.
func (o *ModelsBackup) HasBackupLevel() bool {
	if o != nil && o.BackupLevel != nil {
		return true
	}

	return false
}

// SetBackupLevel gets a reference to the given string and assigns it to the BackupLevel field.
func (o *ModelsBackup) SetBackupLevel(v string) {
	o.BackupLevel = &v
}

// GetBackupTargetId returns the BackupTargetId field value if set, zero value otherwise.
func (o *ModelsBackup) GetBackupTargetId() string {
	if o == nil || o.BackupTargetId == nil {
		var ret string
		return ret
	}
	return *o.BackupTargetId
}

// GetBackupTargetIdOk returns a tuple with the BackupTargetId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetBackupTargetIdOk() (*string, bool) {
	if o == nil || o.BackupTargetId == nil {
		return nil, false
	}
	return o.BackupTargetId, true
}

// HasBackupTargetId returns a boolean if a field has been set.
func (o *ModelsBackup) HasBackupTargetId() bool {
	if o != nil && o.BackupTargetId != nil {
		return true
	}

	return false
}

// SetBackupTargetId gets a reference to the given string and assigns it to the BackupTargetId field.
func (o *ModelsBackup) SetBackupTargetId(v string) {
	o.BackupTargetId = &v
}

// GetBackupType returns the BackupType field value if set, zero value otherwise.
func (o *ModelsBackup) GetBackupType() string {
	if o == nil || o.BackupType == nil {
		var ret string
		return ret
	}
	return *o.BackupType
}

// GetBackupTypeOk returns a tuple with the BackupType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetBackupTypeOk() (*string, bool) {
	if o == nil || o.BackupType == nil {
		return nil, false
	}
	return o.BackupType, true
}

// HasBackupType returns a boolean if a field has been set.
func (o *ModelsBackup) HasBackupType() bool {
	if o != nil && o.BackupType != nil {
		return true
	}

	return false
}

// SetBackupType gets a reference to the given string and assigns it to the BackupType field.
func (o *ModelsBackup) SetBackupType(v string) {
	o.BackupType = &v
}

// GetClusterResourceName returns the ClusterResourceName field value if set, zero value otherwise.
func (o *ModelsBackup) GetClusterResourceName() string {
	if o == nil || o.ClusterResourceName == nil {
		var ret string
		return ret
	}
	return *o.ClusterResourceName
}

// GetClusterResourceNameOk returns a tuple with the ClusterResourceName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetClusterResourceNameOk() (*string, bool) {
	if o == nil || o.ClusterResourceName == nil {
		return nil, false
	}
	return o.ClusterResourceName, true
}

// HasClusterResourceName returns a boolean if a field has been set.
func (o *ModelsBackup) HasClusterResourceName() bool {
	if o != nil && o.ClusterResourceName != nil {
		return true
	}

	return false
}

// SetClusterResourceName gets a reference to the given string and assigns it to the ClusterResourceName field.
func (o *ModelsBackup) SetClusterResourceName(v string) {
	o.ClusterResourceName = &v
}

// GetCreatedAt returns the CreatedAt field value if set, zero value otherwise.
func (o *ModelsBackup) GetCreatedAt() string {
	if o == nil || o.CreatedAt == nil {
		var ret string
		return ret
	}
	return *o.CreatedAt
}

// GetCreatedAtOk returns a tuple with the CreatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetCreatedAtOk() (*string, bool) {
	if o == nil || o.CreatedAt == nil {
		return nil, false
	}
	return o.CreatedAt, true
}

// HasCreatedAt returns a boolean if a field has been set.
func (o *ModelsBackup) HasCreatedAt() bool {
	if o != nil && o.CreatedAt != nil {
		return true
	}

	return false
}

// SetCreatedAt gets a reference to the given string and assigns it to the CreatedAt field.
func (o *ModelsBackup) SetCreatedAt(v string) {
	o.CreatedAt = &v
}

// GetDataServiceId returns the DataServiceId field value if set, zero value otherwise.
func (o *ModelsBackup) GetDataServiceId() string {
	if o == nil || o.DataServiceId == nil {
		var ret string
		return ret
	}
	return *o.DataServiceId
}

// GetDataServiceIdOk returns a tuple with the DataServiceId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetDataServiceIdOk() (*string, bool) {
	if o == nil || o.DataServiceId == nil {
		return nil, false
	}
	return o.DataServiceId, true
}

// HasDataServiceId returns a boolean if a field has been set.
func (o *ModelsBackup) HasDataServiceId() bool {
	if o != nil && o.DataServiceId != nil {
		return true
	}

	return false
}

// SetDataServiceId gets a reference to the given string and assigns it to the DataServiceId field.
func (o *ModelsBackup) SetDataServiceId(v string) {
	o.DataServiceId = &v
}

// GetDeploymentId returns the DeploymentId field value if set, zero value otherwise.
func (o *ModelsBackup) GetDeploymentId() string {
	if o == nil || o.DeploymentId == nil {
		var ret string
		return ret
	}
	return *o.DeploymentId
}

// GetDeploymentIdOk returns a tuple with the DeploymentId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetDeploymentIdOk() (*string, bool) {
	if o == nil || o.DeploymentId == nil {
		return nil, false
	}
	return o.DeploymentId, true
}

// HasDeploymentId returns a boolean if a field has been set.
func (o *ModelsBackup) HasDeploymentId() bool {
	if o != nil && o.DeploymentId != nil {
		return true
	}

	return false
}

// SetDeploymentId gets a reference to the given string and assigns it to the DeploymentId field.
func (o *ModelsBackup) SetDeploymentId(v string) {
	o.DeploymentId = &v
}

// GetDeploymentName returns the DeploymentName field value if set, zero value otherwise.
func (o *ModelsBackup) GetDeploymentName() string {
	if o == nil || o.DeploymentName == nil {
		var ret string
		return ret
	}
	return *o.DeploymentName
}

// GetDeploymentNameOk returns a tuple with the DeploymentName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetDeploymentNameOk() (*string, bool) {
	if o == nil || o.DeploymentName == nil {
		return nil, false
	}
	return o.DeploymentName, true
}

// HasDeploymentName returns a boolean if a field has been set.
func (o *ModelsBackup) HasDeploymentName() bool {
	if o != nil && o.DeploymentName != nil {
		return true
	}

	return false
}

// SetDeploymentName gets a reference to the given string and assigns it to the DeploymentName field.
func (o *ModelsBackup) SetDeploymentName(v string) {
	o.DeploymentName = &v
}

// GetDeploymentTargetId returns the DeploymentTargetId field value if set, zero value otherwise.
func (o *ModelsBackup) GetDeploymentTargetId() string {
	if o == nil || o.DeploymentTargetId == nil {
		var ret string
		return ret
	}
	return *o.DeploymentTargetId
}

// GetDeploymentTargetIdOk returns a tuple with the DeploymentTargetId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetDeploymentTargetIdOk() (*string, bool) {
	if o == nil || o.DeploymentTargetId == nil {
		return nil, false
	}
	return o.DeploymentTargetId, true
}

// HasDeploymentTargetId returns a boolean if a field has been set.
func (o *ModelsBackup) HasDeploymentTargetId() bool {
	if o != nil && o.DeploymentTargetId != nil {
		return true
	}

	return false
}

// SetDeploymentTargetId gets a reference to the given string and assigns it to the DeploymentTargetId field.
func (o *ModelsBackup) SetDeploymentTargetId(v string) {
	o.DeploymentTargetId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *ModelsBackup) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *ModelsBackup) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *ModelsBackup) SetId(v string) {
	o.Id = &v
}

// GetJobHistoryLimit returns the JobHistoryLimit field value if set, zero value otherwise.
func (o *ModelsBackup) GetJobHistoryLimit() int32 {
	if o == nil || o.JobHistoryLimit == nil {
		var ret int32
		return ret
	}
	return *o.JobHistoryLimit
}

// GetJobHistoryLimitOk returns a tuple with the JobHistoryLimit field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetJobHistoryLimitOk() (*int32, bool) {
	if o == nil || o.JobHistoryLimit == nil {
		return nil, false
	}
	return o.JobHistoryLimit, true
}

// HasJobHistoryLimit returns a boolean if a field has been set.
func (o *ModelsBackup) HasJobHistoryLimit() bool {
	if o != nil && o.JobHistoryLimit != nil {
		return true
	}

	return false
}

// SetJobHistoryLimit gets a reference to the given int32 and assigns it to the JobHistoryLimit field.
func (o *ModelsBackup) SetJobHistoryLimit(v int32) {
	o.JobHistoryLimit = &v
}

// GetNamespaceId returns the NamespaceId field value if set, zero value otherwise.
func (o *ModelsBackup) GetNamespaceId() string {
	if o == nil || o.NamespaceId == nil {
		var ret string
		return ret
	}
	return *o.NamespaceId
}

// GetNamespaceIdOk returns a tuple with the NamespaceId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetNamespaceIdOk() (*string, bool) {
	if o == nil || o.NamespaceId == nil {
		return nil, false
	}
	return o.NamespaceId, true
}

// HasNamespaceId returns a boolean if a field has been set.
func (o *ModelsBackup) HasNamespaceId() bool {
	if o != nil && o.NamespaceId != nil {
		return true
	}

	return false
}

// SetNamespaceId gets a reference to the given string and assigns it to the NamespaceId field.
func (o *ModelsBackup) SetNamespaceId(v string) {
	o.NamespaceId = &v
}

// GetProjectId returns the ProjectId field value if set, zero value otherwise.
func (o *ModelsBackup) GetProjectId() string {
	if o == nil || o.ProjectId == nil {
		var ret string
		return ret
	}
	return *o.ProjectId
}

// GetProjectIdOk returns a tuple with the ProjectId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetProjectIdOk() (*string, bool) {
	if o == nil || o.ProjectId == nil {
		return nil, false
	}
	return o.ProjectId, true
}

// HasProjectId returns a boolean if a field has been set.
func (o *ModelsBackup) HasProjectId() bool {
	if o != nil && o.ProjectId != nil {
		return true
	}

	return false
}

// SetProjectId gets a reference to the given string and assigns it to the ProjectId field.
func (o *ModelsBackup) SetProjectId(v string) {
	o.ProjectId = &v
}

// GetReclaimPolicy returns the ReclaimPolicy field value if set, zero value otherwise.
func (o *ModelsBackup) GetReclaimPolicy() string {
	if o == nil || o.ReclaimPolicy == nil {
		var ret string
		return ret
	}
	return *o.ReclaimPolicy
}

// GetReclaimPolicyOk returns a tuple with the ReclaimPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetReclaimPolicyOk() (*string, bool) {
	if o == nil || o.ReclaimPolicy == nil {
		return nil, false
	}
	return o.ReclaimPolicy, true
}

// HasReclaimPolicy returns a boolean if a field has been set.
func (o *ModelsBackup) HasReclaimPolicy() bool {
	if o != nil && o.ReclaimPolicy != nil {
		return true
	}

	return false
}

// SetReclaimPolicy gets a reference to the given string and assigns it to the ReclaimPolicy field.
func (o *ModelsBackup) SetReclaimPolicy(v string) {
	o.ReclaimPolicy = &v
}

// GetSchedule returns the Schedule field value if set, zero value otherwise.
func (o *ModelsBackup) GetSchedule() string {
	if o == nil || o.Schedule == nil {
		var ret string
		return ret
	}
	return *o.Schedule
}

// GetScheduleOk returns a tuple with the Schedule field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetScheduleOk() (*string, bool) {
	if o == nil || o.Schedule == nil {
		return nil, false
	}
	return o.Schedule, true
}

// HasSchedule returns a boolean if a field has been set.
func (o *ModelsBackup) HasSchedule() bool {
	if o != nil && o.Schedule != nil {
		return true
	}

	return false
}

// SetSchedule gets a reference to the given string and assigns it to the Schedule field.
func (o *ModelsBackup) SetSchedule(v string) {
	o.Schedule = &v
}

// GetState returns the State field value if set, zero value otherwise.
func (o *ModelsBackup) GetState() string {
	if o == nil || o.State == nil {
		var ret string
		return ret
	}
	return *o.State
}

// GetStateOk returns a tuple with the State field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetStateOk() (*string, bool) {
	if o == nil || o.State == nil {
		return nil, false
	}
	return o.State, true
}

// HasState returns a boolean if a field has been set.
func (o *ModelsBackup) HasState() bool {
	if o != nil && o.State != nil {
		return true
	}

	return false
}

// SetState gets a reference to the given string and assigns it to the State field.
func (o *ModelsBackup) SetState(v string) {
	o.State = &v
}

// GetSuspend returns the Suspend field value if set, zero value otherwise.
func (o *ModelsBackup) GetSuspend() bool {
	if o == nil || o.Suspend == nil {
		var ret bool
		return ret
	}
	return *o.Suspend
}

// GetSuspendOk returns a tuple with the Suspend field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetSuspendOk() (*bool, bool) {
	if o == nil || o.Suspend == nil {
		return nil, false
	}
	return o.Suspend, true
}

// HasSuspend returns a boolean if a field has been set.
func (o *ModelsBackup) HasSuspend() bool {
	if o != nil && o.Suspend != nil {
		return true
	}

	return false
}

// SetSuspend gets a reference to the given bool and assigns it to the Suspend field.
func (o *ModelsBackup) SetSuspend(v bool) {
	o.Suspend = &v
}

// GetTenantId returns the TenantId field value if set, zero value otherwise.
func (o *ModelsBackup) GetTenantId() string {
	if o == nil || o.TenantId == nil {
		var ret string
		return ret
	}
	return *o.TenantId
}

// GetTenantIdOk returns a tuple with the TenantId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetTenantIdOk() (*string, bool) {
	if o == nil || o.TenantId == nil {
		return nil, false
	}
	return o.TenantId, true
}

// HasTenantId returns a boolean if a field has been set.
func (o *ModelsBackup) HasTenantId() bool {
	if o != nil && o.TenantId != nil {
		return true
	}

	return false
}

// SetTenantId gets a reference to the given string and assigns it to the TenantId field.
func (o *ModelsBackup) SetTenantId(v string) {
	o.TenantId = &v
}

// GetUpdatedAt returns the UpdatedAt field value if set, zero value otherwise.
func (o *ModelsBackup) GetUpdatedAt() string {
	if o == nil || o.UpdatedAt == nil {
		var ret string
		return ret
	}
	return *o.UpdatedAt
}

// GetUpdatedAtOk returns a tuple with the UpdatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ModelsBackup) GetUpdatedAtOk() (*string, bool) {
	if o == nil || o.UpdatedAt == nil {
		return nil, false
	}
	return o.UpdatedAt, true
}

// HasUpdatedAt returns a boolean if a field has been set.
func (o *ModelsBackup) HasUpdatedAt() bool {
	if o != nil && o.UpdatedAt != nil {
		return true
	}

	return false
}

// SetUpdatedAt gets a reference to the given string and assigns it to the UpdatedAt field.
func (o *ModelsBackup) SetUpdatedAt(v string) {
	o.UpdatedAt = &v
}

func (o ModelsBackup) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.AccountId != nil {
		toSerialize["account_id"] = o.AccountId
	}
	if o.BackupLevel != nil {
		toSerialize["backup_level"] = o.BackupLevel
	}
	if o.BackupTargetId != nil {
		toSerialize["backup_target_id"] = o.BackupTargetId
	}
	if o.BackupType != nil {
		toSerialize["backup_type"] = o.BackupType
	}
	if o.ClusterResourceName != nil {
		toSerialize["cluster_resource_name"] = o.ClusterResourceName
	}
	if o.CreatedAt != nil {
		toSerialize["created_at"] = o.CreatedAt
	}
	if o.DataServiceId != nil {
		toSerialize["data_service_id"] = o.DataServiceId
	}
	if o.DeploymentId != nil {
		toSerialize["deployment_id"] = o.DeploymentId
	}
	if o.DeploymentName != nil {
		toSerialize["deployment_name"] = o.DeploymentName
	}
	if o.DeploymentTargetId != nil {
		toSerialize["deployment_target_id"] = o.DeploymentTargetId
	}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.JobHistoryLimit != nil {
		toSerialize["job_history_limit"] = o.JobHistoryLimit
	}
	if o.NamespaceId != nil {
		toSerialize["namespace_id"] = o.NamespaceId
	}
	if o.ProjectId != nil {
		toSerialize["project_id"] = o.ProjectId
	}
	if o.ReclaimPolicy != nil {
		toSerialize["reclaim_policy"] = o.ReclaimPolicy
	}
	if o.Schedule != nil {
		toSerialize["schedule"] = o.Schedule
	}
	if o.State != nil {
		toSerialize["state"] = o.State
	}
	if o.Suspend != nil {
		toSerialize["suspend"] = o.Suspend
	}
	if o.TenantId != nil {
		toSerialize["tenant_id"] = o.TenantId
	}
	if o.UpdatedAt != nil {
		toSerialize["updated_at"] = o.UpdatedAt
	}
	return json.Marshal(toSerialize)
}

type NullableModelsBackup struct {
	value *ModelsBackup
	isSet bool
}

func (v NullableModelsBackup) Get() *ModelsBackup {
	return v.value
}

func (v *NullableModelsBackup) Set(val *ModelsBackup) {
	v.value = val
	v.isSet = true
}

func (v NullableModelsBackup) IsSet() bool {
	return v.isSet
}

func (v *NullableModelsBackup) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableModelsBackup(val *ModelsBackup) *NullableModelsBackup {
	return &NullableModelsBackup{value: val, isSet: true}
}

func (v NullableModelsBackup) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableModelsBackup) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


