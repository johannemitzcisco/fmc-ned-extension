# -*- mode: python; python-indent: 4 -*-
import ncs
import _ncs
from ncs.application import Service
from ncs.dp import Action
import requests
import json
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------------
# ACTIONS EXAMPLE
# ---------------
class ChangePolicy(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output, trans):
        self.log.info('action name: ', name)

        with ncs.maapi.single_read_trans(uinfo.username, 'fmc-extension',
                                         db=ncs.OPERATIONAL) as trans:
            op_root = ncs.maagic.get_root(trans)
            devicerecord = ncs.maagic.get_node(trans, kp)
            fmc_device = devicerecord._parent._parent._parent._parent

            (authgroup, username, password) = getVNFPasswords(self.log, op_root, fmc_device)

            fmc = FMC(fmc_device.address, username, password)
            fmc.tokenGeneration('default')

            accesspolicyid = fmc_device.config.policy.accesspolicies[input.policy]
            deviceId = fmc_device.ciscofmc_id_store.devices.devicerecords[devicerecord.name].id
            fmc.modifyPolicyAssignments(accesspolicyid, "AccessPolicy", deviceId)

def getVNFPasswords(log, root, device):
    authgroup = root.devices.authgroups.group[device.authgroup]
    username = authgroup.default_map.remote_name
    password = _ncs.decrypt(authgroup.default_map.remote_password)
    auths = (authgroup.name, username, password)
    log.info('VNF auths: {}'.format(auths))
    return auths

class FMC (object):
    """Class to define the FMC.
    Attributes
    Host: FMC hostname (FQDN OR IP)
    Username: FMC Username for API user
    Password: FMC Password for API user
    """

    def __init__(self, host, username, password):
        """Return FMC object whose attributes are host, username and password.
        init
        """
        self.host = host
        self.username = username
        self.password = password
        self.headers = {'Content-Type': 'application/json'}
        self.uuid = ""


    def tokenGeneration(self, domain):
            """Generate token."""
            path = "/api/fmc_platform/v1/auth/generatetoken"
            server = "https://"+self.host
            url = server + path
            try:
                req = requests.Session()
                req.trust_env = False
                r = req.post(url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
                auth_headers = r.headers
                token = auth_headers.get('X-auth-access-token', default=None)
                domains = auth_headers.get('DOMAINS', default=None)
                domains = json.loads("{\"domains\":" + domains + "}")
                for item in domains["domains"]:
                    if item["name"] == domain:
                        self.uuid = item["uuid"]
                if token is None:
                        print("No Token found, I'll be back terminating....")
                        sys.exit()
            except Exception as err:
                print ("Error in generating token --> " + str(err))
                sys.exit()
            self.headers['X-auth-access-token'] = token


    def RESTget(self, url):
        """Issue RESTget and update resp and json_resp
           This function will update:
              resp: The complete response from the call
              json_resp: The python dict version of the data
        """
        global resp, json_resp
        time.sleep(1)
        try:
            # REST call with SSL verification turned off:
            req = requests.Session()
            req.trust_env = False
            r = req.get(url, headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.get(url, headers=self.headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            if (status_code == 200):
                # print("GET successful. Response data --> ")
                json_resp = json.loads(resp)
                # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print("Error occurred in GET --> "+resp)
                raise Exception("Error occured in Get -->"+resp)
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> "+str(err))
            raise Exception("Error in connection --> "+str(err))
        finally:
            if r:
                r.close()

    def RESTpost(self, url, post_data):
        """Issue RESTpost and update resp and json_resp
           This function will update:
              resp: The complete response from the call
              json_resp: The python dict version of the data
           """
        global resp, json_resp
        time.sleep(1)
        try:
            # REST call with SSL verification turned off:
            # REST call with SSL verification turned on:
            #r = requests.post(url, data=json.dumps(post_data), headers=self.headers, verify='/path/to/ssl_certificate')
            req = requests.Session()
            req.trust_env = False
            r = req.post(url, data=post_data, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            print("Status code is: "+str(status_code))
            if status_code == 201 or status_code == 202:
                print ("Post was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else :
                r.raise_for_status()
                print ("Error occurred in POST --> "+resp)
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> "+str(err))
            print ("Error occurred in POST --> "+resp)
        finally:
            if r:
                r.close()

    # REST put
    def RESTput(self, url, put_data):
        """Issue RESTput and update resp and json_resp
           This function will update:
              resp: The complete response from the call
              json_resp: The python dict version of the data
           """
        global resp, json_resp
        time.sleep(1)
        try:
            # REST call with SSL verification turned off:
            req = requests.Session()
            req.trust_env = False
            r = req.put(url, data=put_data, headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            if (status_code == 200 or status_code == 201):
                print("Put was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print("Status code:-->"+status_code)
                print("Error occurred in PUT --> "+resp)
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> "+str(err))
            print("Error occurred in PUT --> "+resp)
        finally:
            if r:
                r.close()

    def RESTdelete(self, url):
        """Issue RESTput and update resp and json_resp
           This function will update:
              resp: The complete response from the call
              json_resp: The python dict version of the data
           """
        global resp, json_resp
        time.sleep(1)
        try:
            # REST call with SSL verification turned off:
            req = requests.Session()
            req.trust_env = False
            r = req.delete(url, headers=self.headers, verify=False)
            # REST call with SSL verification turned on:
            # r = requests.put(url, data=json.dumps(put_data), headers=self.headers, verify='/path/to/ssl_certificate')
            status_code = r.status_code
            resp = r.text
            if (status_code == 200):
                print("Delete was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print("Status code:-->"+status_code)
                print("Error occurred in PUT --> "+resp)
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> "+str(err))
        finally:
            if r:
                r.close()

    def createPolicy(self, policyname):
        """Create access policy with data given."""
        path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies"
        server = "https://"+self.host
        url = server + path
        template = JSON_TEMPLATES.get_template('createpolicy.j2.json')
        payload = template.render(name=policyname)
        try:
            r = requests.Session()
            r.trust_env = False
            response = r.post(url, data=payload, headers=self.headers, verify=False)
            status_code = response.status_code
            resp = response.text
            json_response = json.loads(resp)
            print("status code is: " + str(status_code))
            if status_code == 201 or status_code == 202:
                print("Post was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                response.raise_for_status()
                print("error occured in POST -->" + resp)
            return json_response["id"]
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err))
        finally:
            if r:
              r.close()
    
    def deletePolicy(self, data):
        """Delete access policy with data given."""
        path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies/" + str(data)
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.Session()
            r.trust_env = False
            response = r.delete(url, headers=self.headers, verify=False)
            status_code = response.status_code
            resp = response.text
            json_response = json.loads(resp)
            print("status code is: " + str(status_code))
            if status_code == 200:
                print ("Delete was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                response.raise_for_status()
                print ("error occured in Delete -->" + resp)
            return json_response["id"]
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()

    def createRule(self, rulename, policy_id, source_id, dest_id):
        """Create rule with data given."""
        path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies/" + str(policy_id) + "/accessrules"
        server = "https://"+self.host
        url = server + path
        template = JSON_TEMPLATES.get_template('createrule.j2.json')
        payload = template.render(name=rulename, sourceid=source_id, destid=dest_id)
        try:
            r = requests.Session()
            r.trust_env = False
            response = r.post(url, data=payload, headers=self.headers, verify=False)
            status_code = response.status_code
            resp = response.text
            json_response = json.loads(resp)
            print("status code is: " + str(status_code))
            if status_code == 201 or status_code == 202:
                print ("Post was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print ("error occured in POST -->" + resp)
            return True
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()

    def modifyRule(self, rulename, policy_id, access_id, source_id, dest_id):
        """Create rule with data given."""
        path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies/" + str(policy_id) + "/accessrules/" + str(access_id)
        server = "https://"+self.host
        url = server + path
        template = JSON_TEMPLATES.get_template('modifyrule.j2.json')
        payload = template.render(name=rulename, ruleuuid=access_id, sourceid=source_id, destid=dest_id)
        try:
            r = requests.Session()
            r.trust_env = False
            response = r.put(url, data=payload, headers=self.headers, verify=False)
            status_code = response.status_code
            resp = response.text
            json_response = json.loads(resp)
            print("status code is: " + str(status_code))
            if status_code == 201 or status_code == 200:
                print ("Put was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                response.raise_for_status()
                print ("error occured in Put -->" + resp)
            return True
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()

    def deleteRule(self, policy_id, access_id):
        """Delete access policy with data given."""
        path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies/" + str(policy_id) + "/accessrules/" + str(access_id)
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.Session()
            r.trust_env = False
            response = r.delete(url, headers=self.headers, verify=False)
            status_code = response.status_code
            resp = response.text
            json_response = json.loads(resp)
            print("status code is: " + str(status_code))
            if status_code == 200:
                print ("Delete was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            else:
                response.raise_for_status()
                print ("error occured in Delete -->" + resp)
            return json_response["id"]
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()

    def getAccessPolicyIdByName(self, name):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies"
        url = server + api_path
        self.RESTget(url)
        # Search for policy by name
        if 'items' in json_resp:
            for item in json_resp['items']:
                if item['name'] == name:
                    return str(item['id'])
        return ''


    def getPolicyAssignments(self,name):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/assignment/policyassignments"
        url = server + api_path
        self.RESTget(url)
        # Search for policy by name
        if 'items' in json_resp:
            for item in json_resp['items']:
                if item['name'] == name:
                    return str(item['id'])
        return ''
    
    def getPolicyAssignmentsTargetDeviceId(self, policyId):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/assignment/policyassignments/" + str(policyId)
        url = server + api_path
        self.RESTget(url)
        # Search for policy by name
        if 'targets' in json_resp:
            for item in json_resp['targets']:
                    return str(item['id'])
        return ''
    
    def getRulePolicyIdByName(self, name, policy_id):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies/" + str(policy_id) + "/accessrules"
        url = server + api_path
        self.RESTget(url)
        # Search for policy by name
        if 'items' in json_resp:
            for item in json_resp['items']:
                if item['name'] == name:
                    return str(item['id'])
        return ''

       # Create an ftdv nat policy
    def createFtdNatPolicy(self, name, description):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies"
        url = server + api_path
        template = JSON_TEMPLATES.get_template('createftdnat.j2.json')
        payload = template.render(name=name, description=description)
        self.RESTpost(url,payload)
    
    def deleteFtdNatPolicy(self, natpolicyId):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies/" + str(natpolicyId)
        url = server + api_path
        self.RESTdelete(url)

    def getFtdNatPolicyByName(self, name):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies"
        url = server + api_path
        self.RESTget(url)
        # Search for policy by name
        for item in json_resp['items']:
            if item['name'] == name:
                return str(item['id'])
        raise Exception('Policy with name ' + name + ' was not found')

    def associateFtdNatPolicyWithDevice(self, policyName, deviceName):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/assignment/policyassignments"
        url = server + api_path
        post_data = {
            "type": "PolicyAssignment",
            "policy": {
                "type": "FTDNatPolicy",
                "id": self.getFtdNatPolicyByName(policyName)
            },
            "targets": [
                {
                "id": self.getDeviceIdByName(deviceName) ,
                "type": "Device"
                }
            ]
        }
        self.RESTpost(url,post_data)


    def associateFtdNatPolicyWith2Device(self, policyName, deviceName1, deviceName2):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/assignment/policyassignments"
        url = server + api_path
        post_data = {
            "type": "PolicyAssignment",
            "policy": {
                "type": "FTDNatPolicy",
                "id": self.getFtdNatPolicyByName(policyName)
            },
            "targets": [
                {
                "id": self.getDeviceIdByName(deviceName1) ,
                "type": "Device"
                },
                {
                "id": self.getDeviceIdByName(deviceName2) ,
                "type": "Device"
                }
            ]
        }
        self.RESTpost(url,post_data)

    def createFtdNatPolicyManualNatRule(self, natPolicy, description, source, insert):
        global resp, json_resp
        server = "https://"+self.host
        if insert == "before":
            direction = "before_auto"
        elif insert == "after":
            direction = "after_auto"

        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies/" + str(natPolicy) + "/manualnatrules?section=" + direction
        url = server + api_path
        template = JSON_TEMPLATES.get_template('createftdnatmannatrule.j2.json')
        payload = template.render(description=description, osource=source, tsource=source)
        self.RESTpost(url,payload)

    def createFtdNatPolicyAutoNatRule(self, natPolicy, source_id, dest_id, network):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies/" + str(natPolicy) + "/autonatrules"
        url = server + api_path
        template = JSON_TEMPLATES.get_template('createftdnatautonatrule.j2.json')
        payload = template.render(sourceid=source_id, destid=dest_id, network=network)
        self.RESTpost(url,payload)

    def modifyFtdNatPolicyManualNatRule(self, natPolicy, ruleId, source):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies/" + str(natPolicy) + "/manualnatrules/" + str(ruleId)
        url = server + api_path
        template = JSON_TEMPLATES.get_template('modifyftdnatmannatrule.j2.json')
        payload = template.render(mannatruleid=ruleId, osource=source, tsource=source)
        self.RESTput(url,payload)

    def modifyFtdNatPolicyAutoNatRule(self, natPolicy, ruleId, source_id, dest_id, network):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies/" + str(natPolicy) + "/autonatrules/" + str(ruleId)
        url = server + api_path
        template = JSON_TEMPLATES.get_template('modifyftdnatautonatrule.j2.json')
        payload = template.render(autonatruleid=ruleId, sourceid=source_id, destid=dest_id, network=network)
        self.RESTput(url,payload)

    def deleteFtdNatPolicyManualNatRule(self, natPolicy, ruleId):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies/" + str(natPolicy) + "/manualnatrules/" + str(ruleId)
        url = server + api_path
        self.RESTdelete(url)
    
    def deleteFtdNatPolicyAutoNatRule(self, natPolicy, ruleId):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/ftdnatpolicies/" + str(natPolicy) + "/autonatrules/" + str(ruleId)
        url = server + api_path
        self.RESTdelete(url)

    def createAppRule(self, ruleName, policyId, source_id, dest_id, app0, app1, app2, app3):
        global resp, json_resp
        server = "https://"+self.host
        path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies/" + str(policyId) + "/accessrules"
        url = server + path
        template = JSON_TEMPLATES.get_template('createapprule.j2.json')
        payload = template.render(name=ruleName, ruleuuid=policyId, sourceid=source_id, destid=dest_id, appid1=app0, appid2=app1, appid3=app2, appid4=app3)
        self.RESTpost(url,payload)

    def modifyAppRuleAction(self, ruleName, policyId, ruleId, action, source_id, dest_id, app0, app1, app2, app3):
        global resp, json_resp
        server = "https://"+self.host
        path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/policy/accesspolicies/" + str(policyId) + "/accessrules/" + str(ruleId)
        url = server + path
        template = JSON_TEMPLATES.get_template('modifyappruleaction.j2.json')
        payload = template.render(rulename=ruleName, ruleuuid=ruleId, ruleaction=action, sourceid=source_id, destid=dest_id, appid1=app0, appid2=app1, appid3=app2, appid4=app3)
        self.RESTput(url,payload)

    # Get timestamp that can be used for deployment - time*1000
    def fmcGetTimeStamp(self):
        server = "https://"+self.host
        api_path = "/api/fmc_platform/v1/domain/" + str(self.uuid) + "/audit/auditrecords"
        url = server + api_path
        self.RESTget(url)
        return json_resp['items'][0]['time']*1000

    # Deploy to any devices ready for deployment
    def fmcDeploy(self):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/deployment/deployabledevices"
        url = server + api_path
        self.RESTget(url)
        idList = []
        if 'items' in json_resp:
            for item in json_resp['items']:
                if item['type'] == 'DeployableDevice':
                    idList.extend(self.getDeviceIdByName(item['name']))
            print("This is the list to deploy: "+ str(idList) )
            if idList != []:
                api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/deployment/deploymentrequests"
                url = server + api_path
                post_data = {
                    "type": "DeploymentRequest",
                    "version": self.fmcGetTimeStamp(),
                    "forceDeploy": "True",
                    "ignoreWarning": "True",
                    "deviceList": idList
                }
                print(post_data)
                self.RESTpost(url,json.dumps(post_data))
                deploy_status = json_resp['metadata']['task']['links']['self']
                return deploy_status
                    

    def fmcCheckDeployStatus(self,url):
        while True:
            time.sleep(20)
            self.RESTget(url)
            print (json_resp)
            if json_resp['status'] == "Failed":
                print(json_resp)
                raise Exception('Deployment Failed')
                break
            elif json_resp['status'] == "Deployed":
                print ("Successful Deployment")
                break  


    # get Device(FTDv) id by name
    def getDeviceIdByName(self, name):
        """ Returns the device uuid by device name or returns an exception"""
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/devices/devicerecords"
        url = server + api_path
        self.RESTget(url)
        for item in json_resp['items']:
            if item['name'] == name:
                return item['id']
            else:
                ha_id = self.getHAIdToDeploy(name)
                return ha_id
        raise Exception('device with name ' + name + ' was not found')

    def getHAIdToDeploy(self, name):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/deployment/deployabledevices?expanded=true"
        url = server + api_path
        self.RESTget(url)
        idList = []
        print("Beginning to search for " + name)
        if 'items' in json_resp:
            for item in json_resp['items']:
                if 'device' in item:
                    if item['device']['name'] == name:
                        idList.append(item['device']['id'])
        return idList   


    def getDeviceHAPairs(self, name):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/devicehapairs/ftddevicehapairs"
        url = server + api_path
        self.RESTget(url)
        print("here2/n")
        print(name)
        print(json_resp)
        for item in json_resp['items']:
            if item['name'] == name:
                return item['id']
        raise Exception('device with name ' + name + ' was not found')  

    def fn_getSensorIdToDeploy_cs(self):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/deployment/deployabledevices?expanded=true"
        url = server + api_path
        self.RESTget(url)
        idList = []
        print("Beginning...")
        if 'items' in json_resp:
            for item in json_resp['items']:
                if 'deviceMembers' in item:
                    # print(json.dumps(item,sort_keys=True,indent=4, separators=(',', ': '))
                    for device in item['deviceMembers']:
                        if 'type' in device:
                            if device['type'] == "SENSOR":
                                idList.append(device['id'])
        return idList   

    def getInterfaceObjectID(self):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/object/interfaceobjects"
        url = server + api_path
        self.RESTget(url)
        idList = []
        print("Getting ID from Object")
        for item in json_resp['items']:
                if item['type'] == "SecurityZone":
                    idList.append(item['id'])
                    
        print(idList)
        return idList   

    def getNetworkObjectID(self, filtername):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/object/networks"
        url = server + api_path
        self.RESTget(url)
        idList = []
        print("Getting ID from Object")
        if filtername != "":
            for item in json_resp['items']:
                    if item['type'] == "Network":
                        if re.match(filtername, item['name']):
                             print(item)
                             print("Skipping this ID as a match for filter name\n")
                             continue
                        idList.append(item['id'])
        else:
            for item in json_resp['items']:
                    if item['type'] == "Network":
                        idList.append(item['id'])
        print(idList)
        return idList   

    def getApplicationObjectID(self):
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/object/applications"
        url = server + api_path
        self.RESTget(url)
        idList = []
        print("Getting ID from Object")
        for item in json_resp['items']:
            if item['type'] == "Application":
                idList.append(item['id'])
        print(idList)
        return idList   

    def removePolicyAssignments(self, policyassId, policyType):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/assignment/policyassignments/" + str(policyassId)
        url = server + api_path
        template = JSON_TEMPLATES.get_template('removepolicyassignment.j2.json')
        payload = template.render(policyassignmentid=policyassId, policytype=policyType)
        self.RESTput(url,payload)
        return

    def modifyPolicyAssignments(self, policyassId, policyType, deviceId):
        global resp, json_resp
        server = "https://"+self.host
        api_path = "/api/fmc_config/v1/domain/" + str(self.uuid) + "/assignment/policyassignments/" + str(policyassId)
        url = server + api_path
        payload = {
                   "targets": [
                    {
                     "id": "", 
                     "type": "Device"
                    }
                   ],
                   "policy": {
                              "id": "",
                              "type": ""
                   }
                  }
        payload['targets'][0]['id'] = deviceId
        payload['policy']['id'] = policyassId
        payload['policy']['type'] = policyType
        #template = JSON_TEMPLATES.get_template('modifypolicyassignment.j2.json')
        #payload = template.render(policytype=policyType, policyassignmentid=policyassId, devicetargetid=deviceId)
        self.RESTput(url,payload)
        return


#--------------------------------------------
# COMPONENT THREAD THAT WILL BE STARTED BY NCS.
# ---------------------------------------------
class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        with ncs.maapi.Maapi() as m:
            m.install_crypto_keys()

        self.register_action('fmc-ned-extension-action', ChangePolicy)

    def teardown(self):
        self.log.info('Main FINISHED')
