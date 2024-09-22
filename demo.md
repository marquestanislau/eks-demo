topics for the presentation

# Kubernetes Attack Surface
## The problem
## The 4c's of cloud native security

# CIS Benchmark 
## Kube-Bench
Run the kube-bench as a pod and see the logs
```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs kube-bench-pod-name
```

Make a quick fix and run again just for a quick demo

### Authentication
#### Basic authentication mechanism
Static password file

```bash 
# Create a csv file called user-detail.csv
# password,username,userid
password123,user1,u0001
password123,user2,u0002
password123,user3,u0003
password123,user4,u0004
password123,user5,u0005
```

Static basic file
```yaml 
kube-apiserver-arg:
  - 'basic-auth-file=path/to/the/file/user-details.csv'
```

```yaml 
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: # "" indicates the core API group
  resources: ["pods
  verbs: ["get", "watch", "lis

---
# This role binding allows "jane" to read pods in the "default" namespace.
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-pods
  namespace: default5
subjects:
- kind: User
  name: user1 # Name is case sensitive
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role #this must be Role or ClusterRole
  name: pod-reader # this must match the name of the Role or ClusterRole you wish to bind to
  apiGroup: rbac.authorization.k8s.io
```

Static Token file
```bash 
# Create a csv file called user-detail.csv
# password,username,userid
password123,user1,u0001
password123,user2,u0002
password123,user3,u0003
password123,user4,u0004
password123,user5,u0005
```
```yaml 
kube-apiserver-arg:
  - 'token-auth-file=path/to/the/file/user-token-details.csv'
```

```bash
# Restart kubernetes

sudo systemctl daemon-reload
sudo systemctl restart k3s.service

curl -v -k https://master-node-ip:6443/api/v1/pods -u "user1:password123"
```

Service Accounts
```bash
# This is the way to decode tokens
jq -R 'split(".") | select(length > 0) | .[0],.[1] | @base64 | fromjson' <<< <token>
```
### Authorization
Node: will be authenticated by the kube-server if the component belongs to the group and ns of the kuberntes cluster

ABAC: Uses a json file that is evaluated to see if the user or a group contains the permission to access a resource

Cons: Dificult to manage, since you need to update files when a new policy is to be included
```json 
{"kind": "Policy", "spec": {"user": "dev-user", "namespace": "*", "resource": "pods", "apiGroup": "*"}}
```

RBAC: 

developer-role.yaml
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list", "get", "create", "update", "delete"]

- apiGroups: [""]
  resources: ["ConfigMap"]
  verbs: ["create"]
```
Create a role binding object that is used to link a user to the role

devuser-developer-binding.yaml

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: devuser-developer-binding
subjects:
- kind: User
  name: dev-user
  apiGroup: rbac.authorization.K8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io

```
Create the resources and inspect
```bash 
kubectl create -f developer-role.yaml

kubectl create -f devuser-developer-rolebinding.yaml


get roles
get rolebinding


# what if you want to know if you have access to a certain verbs(actions)

kubectl auth can-i create deployments

kubectl auth can-i delete pods/nodes

# or you can do it by inpersionating the user created 

kubectl auth can-i create deployments --as user-dev
kubeclt auth can-i create pods --as dev-user

# or check if it has in a namespace
kubectl auth can-i create deployments --as user-dev --namespace blue
```

# System Hardening
Just a talk with peers

## Linux Syscalls
### Tracing syscalls

```bash 
# see if it is installed 
which strace
strace touch /tmp/error.log

# summary of all syscalls used by touch command
strace -c touch /tmp/error.log

```
## Aquasec Tracee
used to trace system calls at runtime that uses eBPF (extendend Packet Filter)
## Restric syscalls using seccomp
## AppArmor
## Linux Capabilities

# Minimizing Microservices vulnerabilities
## Security Context

## Admission Controllers

```bash
kubectl api-versions | grep admissionregistration.k8s.io
# Namespace autorpovision will be loaded in order for this to work
#this should return an error at first
kubectl run nginx --image nginx -n blue

#Open config file
vim /etc/rancher/k3s/config.yaml
```
The configuration file:

```yaml 
kube-apiserver-arg:
  - 'enable-admission-plugins=NodeRestriction,NamespaceAutoProvision'
```

restart the k3s services

```bash
# Restart kubernetes

sudo systemctl daemon-reload
sudo systemctl restart k3s.service
```


## Pode Security Policies


## OPA in Kubernetes

## Encrypting DAta at rest

## One way SSL vs Mutual SSL


# Supply Chain Security
## Minimize base image footprint

## Image security

## Whitelist allowed registries - Image policy webhook


# Monitor, Logging and Runtime security
## Behavioral analytics of syscall process
 ### Falco


#### Falco in Kubernetes
 ```bash
 #  Configure helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install falco
helm install --replace falco --namespace falco --create-namespace --set tty=true falcosecurity/falco


# check pod status
kubectl get pods -n falco


# Test If falco iwll work by using the default rule
kubectl create deployment nginx --image=nginx

kubectl exec -it $(kubectl get pods --selector=app=nginx -o name) -- cat /etc/shadow


## fetch falco logs and see the warning
kubectl logs -l app.kubernetes.io/name=falco -n falco -c falco | grep Warning

```

_Using a custom Rule:_
```yaml
customRules:
  custom-rules.yaml: |-
    - rule: Write below etc
      desc: An attempt to write to /etc directory
      condition: >
        (evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0)
        and fd.name startswith /etc
      output: "File below /etc opened for writing (file=%fd.name pcmdline=%proc.pcmdline gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4] evt_type=%evt.type user=%user.name user_uid=%user.uid user_loginuid=%user.loginuid process=%proc.name proc_exepath=%proc.exepath parent=%proc.pname command=%proc.cmdline terminal=%proc.tty %container.info)"
      priority: WARNING
      tags: [filesystem, mitre_persistence]    
 
```
Load the custom rule into the running Falco pod/deployment

```bash
helm upgrade --namespace falco falco falcosecurity/falco --set tty=true -f falco_custom_rules_cm.yaml


# Get pod
kubectl wait pods --for=condition=Ready --all -n falco

# Test the rule by triggering it
kubectl exec -it $(kubectl get pods --selector=app=nginx -o name) -- touch /etc/test_file_for_falco_rule

# Validate the rule
kubectl logs -l app.kubernetes.io/name=falco -n falco -c falco | grep Warning

# We can view the logs using a ui tool called falcosidekick UI

helm upgrade --namespace falco falco falcosecurity/falco -f falco_custom_rules_cm.yaml --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=true


kubectl -n falco get svc

# Make it available
kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802

# Trigger an event just for fun
kubectl exec -it $(kubectl get pods --selector=app=nginx -o name) -- cat /etc/shadow


```

#### Falco in ubuntu as a service

```bash
# Just look around the internet, our work was to inform that this is also possible
```

 ### Use Audit Logs to Monitor Access

```yaml
# Will log all metadata that only gets logs in the prod namespace, oppon deletion of a secret
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["prod"]
  verbs: ["delete"]
  resources:
  - group: ""
    resources: ["secrets"]


# Simple example
# sudo mkdir -p -m 700 /var/lib/rancher/k3s/server/logs

apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata


# K3s configuration file location
/etc/rancher/k3s/config.yaml

kube-apiserver-arg:
  - 'audit-log-path=/var/lib/rancher/k3s/server/logs/audit.log'
  - 'audit-policy-file=/var/lib/rancher/k3s/server/audit.yaml'
  - 'audit-log-maxage=30'
  - 'audit-log-maxbackup=10'
  - 'audit-log-maxsize=100'


```

I will need to reload the kubernetes
```bash 
# Restart kubernetes

sudo systemctl daemon-reload
sudo systemctl restart k3s.service

# testing if it will work
# create a ns called prod
# create a secret and then delete it
kubectl create secret generic mysecret --from-literal=password=superpassword -n prod
kubectl get secret -n prod
kubectl delete secret mysecret -n prod
# after deletion go and validate if the event is being logged under the logs directory
cat /var/lib/rancher/k3s/server/logs/audit.log
```

