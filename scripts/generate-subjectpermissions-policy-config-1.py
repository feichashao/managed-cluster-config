#!/usr/bin/env python

import oyaml as yaml
import shutil
import os

rolebinding = \
{'apiVersion': 'rbac.authorization.k8s.io/v1',
'kind': 'RoleBinding',
'metadata': {'name': 'placeholder'},
'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'placeholder'},
'subjects': [{'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'placeholder', 'name': 'placeholder'}]}

clusterrolebinding = \
{'apiVersion': 'rbac.authorization.k8s.io/v1',
'kind': 'ClusterRoleBinding',
'metadata': {'name': 'placeholder'},
'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'placeholder'},
'subjects': [{'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'placeholder', 'name': 'placeholder'}]}

# namespace in SubjectPermission is regex, but namespace selector doesn't support regex
# for most cases using the string match should be enough
# example "(^kube$|^kube-.*|^openshift$|^openshift-.*|^default$|^redhat-.*)"
def regex_to_strings(regex):
    regex = regex.replace("(","")
    regex = regex.replace(")","")
    strings = regex.split("|")
    for i in range(len(strings)):
        strings[i] = strings[i].replace("^","")
        strings[i] = strings[i].replace("$","")
        strings[i] = strings[i].replace(".*","*")
    return strings

manifests = []
policy_name = "test-sp"
temp_directory = os.path.join("/tmp", policy_name + "-subjectpermissions")
configs_directory = os.path.join(temp_directory, "configs")
os.makedirs(temp_directory)
os.makedirs(configs_directory)

sp_yaml="sp_example.yaml"
with open(sp_yaml,'r') as input_file:
    sp_obj = yaml.safe_load(input_file)
    rolebinding_name_prefix = sp_obj["metadata"]["name"]
    # for each clusterpermission, create a non-namespaced clusterrolebinding and a manifest item
    for i in range(len(sp_obj["spec"]["clusterPermissions"])):
        cluster_permission = sp_obj["spec"]["clusterPermissions"][i] 
        clusterrolebinding_name = rolebinding_name_prefix + "-c" + str(i)
        clusterrolebinding["metadata"]["name"] = clusterrolebinding_name
        clusterrolebinding["roleRef"]["name"] = cluster_permission
        clusterrolebinding["subjects"][0]["kind"] = sp_obj["spec"]["subjectKind"]
        clusterrolebinding["subjects"][0]["name"] = sp_obj["spec"]["subjectName"]
        # dump a clusterrolebinding yaml file
        crb_filename = os.path.join(configs_directory, clusterrolebinding_name + ".yaml")
        with open(crb_filename,'w+') as output_file:
            yaml.dump(clusterrolebinding, output_file)
        # create a manifest item for this clusterrolebinding
        manifest = {}
        manifest["path"] = crb_filename
        manifests.append(manifest)

    # for each permission, create a rolebinding yaml file and a manifest item
    for i in range(len(sp_obj["spec"]["permissions"])):
        permission = sp_obj["spec"]["permissions"][i]
        rolebinding_name = rolebinding_name_prefix + "-" + str(i)
        rolebinding["metadata"]["name"] = rolebinding_name
        rolebinding["roleRef"]["name"] = permission["clusterRoleName"]
        rolebinding["subjects"][0]["kind"] = sp_obj["spec"]["subjectKind"]
        rolebinding["subjects"][0]["name"] = sp_obj["spec"]["subjectName"]
        allow_ns = regex_to_strings(permission["namespacesAllowedRegex"])
        deny_ns = regex_to_strings(permission["namespacesDeniedRegex"])
        # dump a rolebinding yaml file
        rb_filename = os.path.join(configs_directory, rolebinding_name + ".yaml")
        with open(rb_filename,'w+') as output_file:
            yaml.dump(rolebinding, output_file)
        # create a manifest item for this rolebinding with namespace selector
        manifest = {}
        manifest["path"] = rb_filename
        manifest["namespaceSelector"] = {}
        manifest["namespaceSelector"]["include"] = allow_ns
        manifest["namespaceSelector"]["exclude"] = deny_ns
        manifests.append(manifest)

# dump the policy generator config with manifests
policy_generator_config = './scripts/policy-generator-config.yaml'
shutil.copy(policy_generator_config, temp_directory)
with open(policy_generator_config,'r') as input_file:
    policy_template = yaml.safe_load(input_file)
#fill in the name and path in the policy generator template
policy_template['metadata']['name'] = 'subjectpermission-policies'
policy_template['policyDefaults']['consolidateManifests'] = False
for p in policy_template['policies']:
    p['name'] =  policy_name + '-sp'
    p['manifests'] = manifests
with open(os.path.join(temp_directory, "policy-generator-config.yaml"),'w+') as output_file:
    yaml.dump(policy_template, output_file)