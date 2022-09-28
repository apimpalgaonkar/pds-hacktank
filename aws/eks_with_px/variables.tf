# tflint-ignore: terraform_unused_declarations
variable "cluster_name" {
  description = "Name of cluster - used by Terratest for e2e test automation"
  type        = string
  default     = "pds-with-px-hanktank"
}

variable "name" {
  description = "Name that can be prefixed/suffixed used to create resources"
  type        = string
  default     = "pds-with-px-hanktank"
}

variable "portworx_eksblueprint_volumeAccess" {
  type        = string
  default     = "portworx_eksblueprint_volumeAccess"
}

variable "region" {
  type        = string
  default     = "us-west-2"
}















