#! /bin/bash
export KUBECONFIG=~/.kube/config

cd ./eks_with_px
echo $(pwd)
terraform init
terraform apply -target="module.vpc" --auto-approve
terraform apply -target="aws_iam_policy.portworx_eksblueprint_volumeAccess" --auto-approve
terraform apply -target="module.eks_blueprints" --auto-approve
terraform apply -target="module.eks_blueprints_kubernetes_addons" --auto-approve

aws eks --region us-east-1 update-kubeconfig --name portworx-eks-iam-policy-hank-tank
cat /root/.kube/config > ./kubeconfig
echo ------ DONE WITH PX INSTALLATION -----
cat $KUBECONFIG

