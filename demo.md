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

# System Hardening

## Least Privilege principle
## Limit Node Access

## SSH hardening
## REstrict kernel modules
## Identify and disable open ports

## Linux Syscalls
## Aquasec Tracee
## Restric syscalls using seccomp
## AppArmor
## Linux Capabilities

# Minimizing Microservices vulnerabilities
## Security Context

## Admission Controllers

```bash
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

