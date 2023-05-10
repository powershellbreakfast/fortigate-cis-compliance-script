
import argparse
import pathlib
import pandas
import requests
import urllib3
from datetime import datetime
import time
import re


#Normal
def read_regular_config(config_file_path):
    with open (config_file_path,"r") as config_file:
        text_config = config_file.read()

    return text_config
#YAML

timezone_dict = {
        "01":"-1100",
        "02":"-1000",
        "03":"-0900",
        "04":"-0800",
        "05":"-0700",
        "81":"-0700",
        "06":"-0700",
        "07":"-0600",
        "08":"-0600",
        "09":"-0600",
        "10":"-0600",
        "11":"-0500",
        "12":"-0500",
        "13":"-0500",
        "74":"-0400",
        "14":"-0400",
        "77":"-0400",
        "15":"-0400",
        "87":"-0400",
        "16":"-0300",
        "17":"-0330",
        "18":"-0300",
        "19":"-0300",
        "20":"-0300",
        "75":"-0300",
        "21":"-0200",
        "22":"-0100",
        "23":"-0100",
        "24":"+0000",
        "80":"+0000",
        "79":"+0000",
        "25":"+0000",
        "26":"+0100",
        "27":"+0100",
        "28":"+0100",
        "78":"+0100",
        "29":"+0100",
        "30":"+0100",
        "31":"+0200",
        "32":"+0200",
        "33":"+0200",
        "34":"+0200",
        "35":"+0200",
        "36":"+0200",
        "37":"+0300",
        "38":"+0300",
        "83":"+0300",
        "84":"+0300",
        "40":"+0300",
        "85":"+0300",
        "39":"+0300",
        "41":"+0330",
        "42":"+0400",
        "43":"+0400",
        "44":"+0430",
        "45":"+0500",
        "46":"+0500",
        "47":"+0530",
        "51":"+0530",
        "48":"+0545",
        "49":"+0600",
        "50":"+0600",
        "52":"+0630",
        "53":"+0700",
        "54":"+0700",
        "55":"+0800",
        "56":"+0800",
        "57":"+0800",
        "58":"+0800",
        "59":"+0800",
        "60":"+0900",
        "61":"+0900",
        "62":"+0930",
        "63":"+0930",
        "64":"+1000",
        "65":"+1000",
        "66":"+1000",
        "67":"+1000",
        "68":"+1000",
        "69":"+1000",
        "70":"+1100",
        "71":"+1200",
        "72":"+1200",
        "00":"+1200",
        "82":"+1245",
        "73":"+1300",
        "86":"+1300",
        "76":"+1400"
    }

class FortiGateAPI:
    def __init__(self):
        self.base_url = f"{args.url}/api/v2"
        self.api_key = args.key
        self.meta_data = {}
        self.debug = False
        urllib3.disable_warnings()

    def get(self,path:str,param_dict:dict={}):
        param_dict["access_token"] = self.api_key
        response = requests.get(self.base_url+path,params=param_dict,verify=False)
        if self.debug:
            print(response.text)
        results = response.json()["results"]
        meta = response.json()
        del meta["results"]
        self.meta_data = meta
        return results

    def get_raw(self,path:str,param_dict:dict={}):
        param_dict["access_token"] = self.api_key
        response = requests.get(self.base_url+path,params=param_dict,verify=False)
        if self.debug:
            print(response.text)
        return response.text



class api_checks:
    def __init__(self):
        pass
    #3.4 Ensure there are no Unused Policies (Manual)
    def no_unused_policies(self,max_score):
        data = api.get(path="/monitor/firewall/policy")
        score = max_score
        reason = ""
        isPass = False
        score_per_policy = max_score/len(data)
        for policy in data:
            try:
                hit_count = policy['hit_count']
            except:
                hit_count = policy['packets']
            if hit_count < 1:
                reason += f"PolicyId: {policy['policyid']} Is not used, "
                score -= score_per_policy
        
        if reason == "":
            reason = "All policies are used by network traffic"
            isPass = True

        return (score, isPass, reason)

    #1.1 Ensure DNS server is configured (Manual)
    def dns_configured(self,max_score):
        data = api.get(path="/cmdb/system/dns")
        score = max_score
        primary_dns_ip = data['primary']
        secondary_dns_ip = data['secondary']
        if primary_dns_ip == "0.0.0.0":
            score = 0
            reason = f"Primary DNS not set"
            isPass = False
        elif secondary_dns_ip == "0.0.0.0":
            score = max_score/2
            reason = f"Secondary DNS not set"
            isPass = False
        else:
            score = max_score
            isPass = True
            reason = "Redunant DNS Configured"
        return (score, isPass, reason)

    #1.2 Ensure intra-zone traffic is not always allowed (Manual)
    def deny_intrazone(self,max_score):
        data = api.get(path="/cmdb/system/zone")
        score = max_score
        isPass = True
        reason = "Intrazone Traffic Blocked"
        points_per_zone = max_score/len(data) 
        for zone in data:
            zone_name = zone['name']
            intrazone_traffic = zone['intrazone']
            if intrazone_traffic == "allow":
                score -= points_per_zone
                reason = f"Zone: {zone_name} allows intra-zone traffic"
                isPass = False
        return (score, isPass, reason)

    #2.1.1 Ensure 'Pre-Login Banner' is set (Manual)
    def pre_login_banners_set(self,max_score):
        data = api.get(path="/cmdb/system/global")
        pre_login_banner = data['pre-login-banner']
        score = max_score
        reason = "Pre-Login Banner is set!"
        isPass = True
        if pre_login_banner == "disable":
            reason = f"Pre-Login Banner not set!"
            isPass = False
            score = 0
        return (score, isPass, reason)

    #2.1.2 Ensure 'Post-Login-Banner' is set (Manual)
    def post_login_banners_set(self,max_score):
        data = api.get(path="/cmdb/system/global")
        post_login_banner = data['post-login-banner']
        score = max_score
        reason = "Post-Login Banner is set!"
        isPass = True
        if post_login_banner == "disable":
            reason = f"Post-Login Banner not set!"
            isPass = False
            score = 0
        return (score, isPass, reason)

    #2.1.3 Ensure timezone is properly configured (Manual)
    def timezone_set(self,max_score):
        data = api.get(path="/cmdb/system/global")
        firewall_timezone_code = data['timezone']
        timezone_dict = {
        "01":"-1100",
        "02":"-1000",
        "03":"-0900",
        "04":"-0800",
        "05":"-0700",
        "81":"-0700",
        "06":"-0700",
        "07":"-0600",
        "08":"-0600",
        "09":"-0600",
        "10":"-0600",
        "11":"-0500",
        "12":"-0500",
        "13":"-0500",
        "74":"-0400",
        "14":"-0400",
        "77":"-0400",
        "15":"-0400",
        "87":"-0400",
        "16":"-0300",
        "17":"-0330",
        "18":"-0300",
        "19":"-0300",
        "20":"-0300",
        "75":"-0300",
        "21":"-0200",
        "22":"-0100",
        "23":"-0100",
        "24":"+0000",
        "80":"+0000",
        "79":"+0000",
        "25":"+0000",
        "26":"+0100",
        "27":"+0100",
        "28":"+0100",
        "78":"+0100",
        "29":"+0100",
        "30":"+0100",
        "31":"+0200",
        "32":"+0200",
        "33":"+0200",
        "34":"+0200",
        "35":"+0200",
        "36":"+0200",
        "37":"+0300",
        "38":"+0300",
        "83":"+0300",
        "84":"+0300",
        "40":"+0300",
        "85":"+0300",
        "39":"+0300",
        "41":"+0330",
        "42":"+0400",
        "43":"+0400",
        "44":"+0430",
        "45":"+0500",
        "46":"+0500",
        "47":"+0530",
        "51":"+0530",
        "48":"+0545",
        "49":"+0600",
        "50":"+0600",
        "52":"+0630",
        "53":"+0700",
        "54":"+0700",
        "55":"+0800",
        "56":"+0800",
        "57":"+0800",
        "58":"+0800",
        "59":"+0800",
        "60":"+0900",
        "61":"+0900",
        "62":"+0930",
        "63":"+0930",
        "64":"+1000",
        "65":"+1000",
        "66":"+1000",
        "67":"+1000",
        "68":"+1000",
        "69":"+1000",
        "70":"+1100",
        "71":"+1200",
        "72":"+1200",
        "00":"+1200",
        "82":"+1245",
        "73":"+1300",
        "86":"+1300",
        "76":"+1400"
    }
        computer_timzone = time.strftime('%z')
        firewall_timezone = timezone_dict[firewall_timezone_code]
        if computer_timzone == firewall_timezone:
            return (max_score, True, "Firewall timezone matchs timezone of the computer this was run on.")
        else:
            return (0, False, "Firewall timezone Does not match timezone of the computer this was run on.")

    #2.1.4 Ensure correct system time is configured through NTP (Manual)
    def ntp_configured(self,max_score):
        data = api.get("/cmdb/system/ntp")
        #check for fortiguard modes
        ntp_sync = data['ntpsync']
        if ntp_sync == "disable":
            score = 0
            isPass = False
            reason = "NTP is Disabled"
        else:
            if data['type'] == "custom":
                #check for configured server
                if len(data['ntpserver']) > 0:
                    score = max_score
                    isPass = True
                    reason = "NTP is Enabled and at least 1 NTP Server was configured"
                else:
                    score = 0
                    isPass = False
                    reason = "NTP is Enabled but no NTP Servers were configured"
            else:
                score = max_score
                isPass = True
                reason = "NTP is Enabled and using FortiGuard servers"
            
        return (score , isPass , reason)
        

        
    #2.1.5 Ensure hostname is set (Manual)
    def hostname_set(self,max_score):
        #By default, the name (Host Name) of a FortiGate unit is the model number of the unit or the serial number.
        # data_model = api.get("/monitor/system/status")
        data_hostname = api.get("/cmdb/system/global")
        serial_number = api.meta_data['serial']
        alias = data_hostname['alias']
        hostname = data_hostname['hostname']
        if hostname == serial_number or hostname == alias:
            score = 0
            isPass = False
            reason = "Hostname Unchanged"
        else:
            score = max_score
            isPass = True
            reason = "Custom Hostname Set"
        
        return (score , isPass , reason)
    #2.1.6 Ensure the latest firmware is installed (Manual)
    def latest_firmware_installed(self,max_score):
        firmware = api.get("/monitor/system/firmware")
        current_firmware = firmware['current']
        avaliable_firmwares = firmware['available']
        firmware_score = max_score
        score_update = firmware_score
        reason ="firmware is current"
        for fw in avaliable_firmwares:
            if fw['major'] > current_firmware['major']:
                #firmware has major update check maturity
                if current_firmware['maturity'] == 'M':
                    score_update = max_score * .5
                    reason ="major update exists and your current fw is mature"
                else:
                    score_update = 0
                    reason ="major update exists and your current fw is not mature"

            elif fw['major'] == current_firmware['major']:
                #firmware is on current major version, check for minor updates
                if fw['minor'] > current_firmware['minor']:
                    #firmware has minor update check maturity
                    if current_firmware['maturity'] == 'M':
                        score_update = max_score * .75
                        reason ="minor update exists and your current fw is mature"
                    else:
                        score_update = max_score * .5
                        reason ="minor update exists and your current fw is not mature"
            
                elif fw['minor'] == current_firmware['minor']:
                    if fw['patch'] > current_firmware['patch']:
                        #firmware has patch check maturity
                        if current_firmware['maturity'] == 'M':
                            score_update = max_score * .90
                            reason ="patch exists and your current fw is mature"
                        else:
                            score_update = max_score * .75
                            reason ="patch exists and your current fw is not mature"
                
                    elif fw['patch'] == current_firmware['patch']:
                        #firmware is current 
                        reason = "firmware is current"
            else:
                #debug print only
                #print(f"older ignore version:{fw['version']}")
                pass

            if score_update < firmware_score:
                firmware_score = score_update 

        if firmware_score == float(max_score):
            isPass = True
        else:
            isPass = False

        return (firmware_score , isPass , reason)
    #2.1.7 Disable USB Firmware and configuration installation (Manual)
    def usb_fw_disabled(self,max_score):
        data = api.get("/cmdb/system/auto-install")
        score = max_score
        reason = ""
        if data['auto-install-config'] == "enable":
            score -= max_score/2
            isPass = False
            reason += "Auto install Config Enabled, "
        if data['auto-install-image'] == "enable":
            score -= max_score/2
            reason += "Auto install Image Enabled"
            isPass = False

        if reason == "":
            reason = "USB Fireware Upload disabled"
            isPass = True 

        return (score , isPass , reason)

    #2.1.8 Disable static keys for TLS (Manual)
    def static_keys_tls(self,max_score):
        data = api.get("/cmdb/system/global")
        
        if data['ssl-static-key-ciphers'] == "enable":
            score = 0
            reason = "SSL Static key Ciphers is Enabled"
            isPass = False
        else:
            score = max_score
            reason = "SSL Static key Ciphers is Disabled"
            isPass = True

        return (score , isPass , reason)
    #2.1.9 Enable Global Strong Encryption (Manual)
    def strong_encryption(self,max_score):
        data = api.get("/cmdb/system/global")
        score = max_score
        if data['strong-crypto'] == "disable":
            score = 0
            reason = "strong crypto is Disabled"
            isPass = False
        else:
            score = max_score
            reason = "strong crypto is Enabled"
            isPass = True

        return (score , isPass , reason)

    #2.2.1 Ensure 'Password Policy' is enabled (Manual)
    def password_policy(self,max_score):
        data = api.get("/cmdb/system/password-policy")

        if data['status'] == "disable":
            score = 0
            reason = "Password Policy is Disabled"
            isPass = False
        else:
            score = max_score
            reason = "Password Policy is Enabled"
            isPass = True

        return (score , isPass , reason)

    #2.2.2 Ensure administrator password retries and lockout time are configured (Manual)
    def admin_lockout(self,max_score):
        data = api.get("/cmdb/system/global")
        score = max_score
        reason = ""
        isPass = False
        if data['admin-lockout-threshold'] < 5:
            reason += "Admin Failed Password Threshold too Low, "
            score -= max_score/2
        if 60 < data['admin-lockout-duration']:
            reason += "Admin Lockout Duration too Low, "
            score -= max_score/2
        if 3600 < data['admin-lockout-duration']:
            reason += "Admin Lockout Duration higher than 1hr, May cause issues"
        
        if reason == "":
            reason = "Admin Lockout policy is within spec"
            isPass = True 

        return (score , isPass , reason)

    #2.3.1 Ensure SNMP agent is disabled (Manual)
    #2.3.2 Ensure only SNMPv3 is enabled (Manual)
    def snmp_agentv12_disabled(self,max_score):
        data = api.get("/cmdb/system.snmp/sysinfo")
        if data['status'] == "enable":
            community_data = api.get("/cmdb/system.snmp/community")
            if len(community_data) > 0:
                #v12 enabled
                return (0 , False , "SNMP v1/v2 is enabled")
            else:
                return (max_score , True , "SNMP v1/v2 is Disabled")     

    def snmpv3_user(self,max_score):
        data = api.get("/cmdb/system.snmp/sysinfo")
        if data['status'] == "enable":
            reason = "SNMP v3 Enabled, "
            score = max_score
            isPass = False
            #v3 enabled, is configured properly
            user_data = api.get("/cmdb/system.snmp/user")
            if len(user_data) > 0: 
                points_per_user = max_score/len(user_data)
                for snmp_user in user_data:
                    if snmp_user['security-level'] != "auth-priv":
                        reason += f"SNMP v3 User {snmp_user['name']} has weak security, "
                        score -= points_per_user
                        
                if reason == "SNMP v3 Enabled, ":
                    isPass = True
                    reason = "SNMP v3 Enabled and configured securely"

                return (score , isPass , reason)
            else:
                return (max_score , True , "SNMPv3 Enabled but no users are configured")
        else:
            return (max_score , True , "SNMPv3 Disabled")


    #2.4.4 Ensure idle timeout time is configured (Manual)
    def idle_timeout(self,max_score):
        data = api.get("/cmdb/system/global")
        if data['admintimeout'] > 15:
            return (0 , False , "idle timeout exceeds 15 minuted")
        if data['admintimeout'] == 0:
            return (0 , False , "idle timeout disabled")
        return (max_score , True , "idle timeout enabled and under 15 minutes")


    #2.4.5 Ensure only encrypted access channels are enabled (Manual)
    def encrypted_access(self,max_score):
        data = api.get("/cmdb/system/interface")
        score = max_score
        reason = ""
        points_per_interface = max_score/len(data)
        for interface in data:
            allow_access_string = interface['allowaccess']
            allow_access_array = allow_access_string.split(" ")
            if "http" in allow_access_array or "telnet" in allow_access_array:
                score -= points_per_interface
                reason += f"Interface: {interface['name']} allows insecure access method, "
                isPass = False

        if reason == "":
            isPass = True
            reason = "No Interfaces allow insecure access methods"
        score = round(score,1)
        
        return (score , isPass , reason)

    #2.5.1 Ensure High Availability Configuration (Manual)
    def ha_setup(self,max_score):
        data = api.get("/cmdb/system/ha")
        if data['mode'] != 'standalone' and data['password'] != "" and data['group-name'] != "" and data['hbdev'] != "":
            return (max_score , True , "HA is configured")
        else:
            return (0 , False , "HA is not configured")
    #2.5.2 Ensure "Monitor Interfaces" for High Availability Devices is Enabled (Manual)
    def ha_monitored_interfaces(self,max_score):
        data = api.get("/cmdb/system/ha")
        if data['monitor'] != "":
            return (max_score , True , "Interface Monitoring is enabled for HA")
        else:
            return (0 , False , "Interface Monitoring is not enabled for HA")
    #2.5.3 Ensure HA Reserved Management Interface is Configured (Manual)
    def ha_reserved_mgmt_int(self,max_score):
        data = api.get("/cmdb/system/ha")
        if data['ha-mgmt-status'] == "enable" and len(data['ha-mgmt-interfaces']) > 0:
            return (max_score , True , "HA has Reserve Managment Interface configured")
        else:
            return (0 , False , "HA has no Reserve Managment Interface")

    #3.2 Ensure that policies do not use "ALL" as Service (Manual)
    def service_all_policies(self,max_score):
        data = api.get("/cmdb/firewall/policy")
        all_service = {'name': 'ALL', 'q_origin_key': 'ALL'}
        points_per_policy = max_score/len(data)
        score = max_score
        isPass = False
        reason = ""
        for policy in data:
            if all_service in policy['service']:
                score -= points_per_policy
                reason += f"Policy:{policy['name']} permits all services/ports, "
        
        if reason == "":
            isPass = True
            reason = "No Policies Allow All services"

        return (score , isPass , reason)

    #4.1.1 Detect Botnet Connections (Manual)
    def detect_botnet_connections(self,max_score):
        data_interfaces = api.get("/cmdb/system/interface")
        data_sdwan = api.get("/cmdb/system/sdwan")
        data_policies = api.get("/cmdb/firewall/policy")

        wan_interfaces = []
        for interface in data_interfaces:
            if interface['role'] == "wan":
                wan_interfaces.append(interface['name'])

        for sdwan_zone in data_sdwan['zone']:
            wan_interfaces.append(sdwan_zone['name'])

        reason = ""
        isPass = False
        score = max_score
        for policy in data_policies:
            for dest_interface in policy['dstintf']:
                if dest_interface['name'] in wan_interfaces:
                    ips = api.get(f"/cmdb/ips/sensor/{policy['ips-sensor']}")
                    if ips[0]['scan-botnet-connections'] != "block":
                        reason += f"Policy: {policy['name']} Botnet Connections not blocked on outbound rule, "
                        score = 0

        if reason == "":
            isPass = True
            reason = "Botnet Detection is enabled for all IPS Sensors applied to Outbound Policies"

        return (score , isPass , reason)

    #4.2.1 Ensure Antivirus Definition Push Updates are Configured (Manual)
    def av_push_updates(self,max_score):
        data = api.get("/cmdb/system.autoupdate/schedule")
        if data['status'] == "enable":
            return (max_score , True , "AV updates enabled")
        else:
            return (0 , False , "AV updates disabled")

    #4.2.2 Apply Antivirus Security Profile to Policies (Manual)
    def av_all_policies(self,max_score):
        data_policies = api.get("/cmdb/firewall/policy")
        points_per_policy = max_score/len(data_policies)
        reason = ""
        isPass = False
        score = max_score
        for policy in data_policies:
            if policy['av-profile'] == '':
                score -= points_per_policy
                reason += f"Policy {policy['name']} has no AV profile applied, "
        
        if reason == "":
                isPass = True
                reason = "AV profiles are applied to all Policies"

        score = round(score,1)

        return (score , isPass , reason)

    #4.3.1 Enable Botnet C&C Domain Blocking DNS Filter (Manual)
    def dns_block_cnc_score(self,max_score):
        data_interfaces = api.get("/cmdb/system/interface")
        data_sdwan = api.get("/cmdb/system/sdwan")
        data_policies = api.get("/cmdb/firewall/policy")

        wan_interfaces = []
        for interface in data_interfaces:
            if interface['role'] == "wan":
                wan_interfaces.append(interface['name'])

        for sdwan_zone in data_sdwan['zone']:
            wan_interfaces.append(sdwan_zone['name'])
        reason = ""
        isPass = False
        score = max_score
        for policy in data_policies:
            for dest_interface in policy['dstintf']:
                if dest_interface['name'] in wan_interfaces:
                    dns = api.get(f"/cmdb/dnsfilter/profile/{policy['dnsfilter-profile']}")
                    #print(dns)
                    if dns[0]['block-botnet'] != "disable":
                        reason += f"Policy:{policy['name']} Botnet Connections not blocked on outbound rule, "
                        score = 0

        if reason == "":
                isPass = True
                reason = "All outbound policies have DNS filter applied with Botnet C&C domain blocking enabled"

        return (score , isPass , reason)

    #5.1.1 Enable Compromised Host Quarantine (Manual) (requires EMS + FAZ)
    def auto_quarntine_host_enabled(self,max_score):
        data = api.get("/cmdb/system/automation-stitch/Compromised Host Quarantine")
        if data[0]['status'] == 'enable':
            return (max_score , True , "Compromised Host Automation Quarantine Rule is enabled.")
        else:
            return (0 , False , "Compromised Host Automation Quarantine Rule is Disabled.")

    #5.2.1.1 Ensure Security Fabric is Configured (Manual)
    def security_fabric_configured(self,max_score):
        data = api.get("/cmdb/system/csf")
        isPass = False
        reason = ""
        score = max_score
        if data["status"] == "enable":
            if data['group-name'] == "":
                reason += "Security Fabric has no group Name, "
                score -= max_score/2
            if data['group-password'] == "":
                reason += "Security Fabric has no group password, "
                score -= max_score/2
        else:
            reason = "Security Fabric Disabled!"
            score = 0
            

        if reason == "":
            isPass = True
            reason = "Security Fabric Enabled and configured"

        return (score , isPass , reason)



    #6.1.2 Enable Limited TLS Versions for SSL VPN (Manual)
    def ssl_vpn_ciphers_limited(self,max_score):
        #is SSL VPN portal setup ?
        data = api.get("/cmdb/vpn.ssl/settings")
        safe_tls_versions = ["tls1-3","tls1-2"]
        if data["status"] == "enable":
            if data['ssl-min-proto-ver'] not in safe_tls_versions:
                return (0 , False , "SSLVPN is Enabled and configured to older non-secure versions of TLS/SSL")
            else:
                return (max_score , True , "SSLVPN is Enabled and configured to use tls 1.2 and 1.3 only")
        else:
            return (max_score , True , "SSLVPN is disabled.")
    #7.1 Configuring the maximum login attempts and lockout period (Manual)
    def user_lockout(self,max_score):
        data = api.get("/cmdb/user/setting")
        isPass = False
        reason = ""
        score = max_score
        if data["auth-lockout-threshold"] > 5:
            score -= max_score/2
            reason += "Password retry threshold is too high, "
        if data["auth-lockout-duration"] < 300:
            score -= max_score/2
            reason += "Failed login lockout duration is too low, "
        
        if reason == "":
            isPass = True
            reason = "User Lockout Policy properly configured"

        return (score , isPass , reason)

    #8.1.1 Enable Event Logging (Manual)
    def enable_event_logging_score(self,max_score):
        data = api.get("/cmdb/log/eventfilter")
        if data["event"] == "enable":
            return (max_score , True , "Event logging is enabled.")
        else:
            return (0 , False , "Event logging is Disabled.")
    #8.2.1 Encrypt Log Transmission to FortiAnalyzer / FortiManager (Manual)
    def encrypted_log_transmission(self,max_score):
        data = api.get("/cmdb/log.fortianalyzer/setting")
        if data['enc-algorithm'] == "high":
            return (max_score , True , "Log Transmission to Fortigate and Fortianalyzer encryption is set to high.")
        else:
            return (0 , False , "Log Transmission to Fortigate and Fortianalyzer encryption is not set to high.")
    #8.3.1 Centralized Logging and Reporting (Manual)
    def central_logging_configured(self,max_score):
        data = api.get("/monitor/log/device/state")
        syslogd = api.get("/cmdb/log.syslogd/setting")

        if data["fortianalyzer"]["is_enabled"]:
            return (max_score , True , "FortiAnalzer logging is enabled.")
        elif data["fortianalyzer_cloud"]["is_enabled"]:
            return (max_score , True , "FortiAnalyzer cloud logging is enabled.")
        elif data["forticloud"]["is_enabled"]:
            return (max_score , True , "FortiCloud logging is enabled.")
        elif syslogd["status"] == "enable":
            return (max_score/2 , True , "Syslog logging is enabled.")
        else:
            return (0 , False , "No central logging is enabled.")
api_checks = api_checks()
class config_checks:
    def __init__(self):
        pass
    #1.1 Ensure DNS server is configured (Manual)
    def check_dns_configured(self,max_score,config):
        # define a Regex Pattern
        pattern = re.compile('config system dns[a-zA-Z0-9 .\s"]*end\n')
        # search all lines for pattern
        match = pattern.search(config)
        if match:
            dns_settings = match.group()
            ipv4_pattern = re.compile('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')
            ipv6_pattern = re.compile('[0-9a-fA-F]{4}:[0-9a-fA-F:]{4,40}')
            ip_pattern = re.compile('([0-9a-fA-F]{4}:[0-9a-fA-F:]{4,40})|(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
            ip_match = ip_pattern.findall(dns_settings)
            if len(ip_match) >= 2:
                return (max_score , True , "2 or more DNS Servers configured")
            elif len(ip_match) == 1:
                return (max_score/2 , False , "Only 1 dns Server")
            else:
                return (0 , False , "No DNS Servers!")
        else:
            print("no match was found!")
        # get context for the match 
        raise Exception("Error DNS Settings were not found !")

    #1.2 Ensure intra-zone traffic is not always allowed (Manual)
    def check_intrazone_denied(self,max_score,config):
        zone_settings_pattern = re.compile('config system zone[a-zA-Z0-9 \s"]*end')
        zone_settings = zone_settings_pattern.search(config)
        if zone_settings:
            zone_pattern = re.compile(' *edit[ \n\"\w]*?next')
            zone_settings_match = zone_settings.group()
            zones_matched = zone_pattern.findall(zone_settings_match)
            if len(zones_matched) > 0:
                zone_name_pattern = re.compile('edit \"[\w ]*\"\n')
                intra_zone_allow = re.compile('set intrazone allow')
                zones_allowed_count = 0
                score = max_score 
                isPass = False
                reason = ""
                points_per_zone = max_score/len(zones_matched)
                for zone_match in zones_matched:
                    is_intra_zone_allowed = intra_zone_allow.search(zone_match)
                    zone_name = (zone_name_pattern.search(zone_match).group()).split('"')[1]
                    if is_intra_zone_allowed:
                        reason += f"Zone: {zone_name} allows intra-zone Traffic, "
                        score -= points_per_zone
                if reason == "":
                    isPass = True
                    reason = "All zones block intra-zone traffic"

                return (score , isPass , reason)
            else: 
                raise Exception("Error ZONES were not found in ZONE Settings!")
        else:
            raise Exception("Error ZONE Settings were not found !")

    #2.1.1 Ensure 'Pre-Login Banner' is set (Manual)
    def check_prelogin_banner(self,max_score,config):
        sys_global_patten = re.compile('config system global[\w\s\-\"]*?end')
        sys_global = sys_global_patten.search(config)
        if sys_global:
            pre_login_pattern = re.compile('set pre-login-banner enable')
            is_pre_login_enabled = pre_login_pattern.search(sys_global.group())
            if is_pre_login_enabled:
                return (max_score , True , "Pre-Login Banner Enabled!")
            else:
                return (0 , False , "Pre-Login Banner Disabled!")
        else:
            raise Exception("Error System Global Settings were not found !")


    #2.1.2 Ensure 'Post-Login-Banner' is set (Manual)
    def check_postlogin_banner(self,max_score,config):
        sys_global_patten = re.compile('config system global[\w\s\-\"]*?end')
        sys_global = sys_global_patten.search(config)
        if sys_global:
            post_login_pattern = re.compile('set post-login-banner enable')
            is_post_login_enabled = post_login_pattern.search(sys_global.group())
            if is_post_login_enabled:
                return (max_score , True , "Post-Login Banner Enabled!")
            else:
                return (0 , False ,"Post-Login Banner Disabled!")

    #2.1.3 Ensure timezone is properly configured (Manual
    def check_timezone_configured(self,max_score,config):
        #get current time zone
        comp_tz = time.strftime('%z')
        #parse FGT time zone
        tz_pattern = re.compile(' {4}set timezone \d{2}\n')
        tz_num_pattern = re.compile('\d{2}')
        fgt_tz_setting = tz_pattern.search(config).group()
        fgt_tz_num = tz_num_pattern.search(fgt_tz_setting).group()
        fgt_tz = timezone_dict[fgt_tz_num]
        print(f"local:{comp_tz} fgt_num:{fgt_tz_num} fgt:{fgt_tz}")
        if comp_tz == fgt_tz:
            return (max_score , True , "Fortigate configured Timezone Matches Computer Timezone")
        else:
            return (0 , False ,"Fortigate configured Timezone Doesn't Match Computer Timezone")

    #2.1.4 Ensure correct system time is configured through NTP (Manual)
    def check_ntp_configured(self,max_score,config):
        ntp_settings_pattern = re.compile('config system ntp[\w\s\-"]*?end')
        ntp_settings = ntp_settings_pattern.search(config).group()
        #if ntpsync enable is true, it does not show if not set to enable
        ntp_sync_pattern = re.compile('set ntpsync enable')
        ntp_sync_enable = ntp_sync_pattern.search(ntp_settings)
        if ntp_sync_enable:
            return (max_score , True , "NTP Sync Enabled")
        else:
            return (0 , False ,"NTP Sync Disabled")

        #TODO: Add detection of custom vs fortiguard servers?

    #TODO 2.1.5 Ensure hostname is set (Manual)
    def check_hostname_configured(self,max_score,config):
        #by default the hostname is the Serial Number or Model Number.
        system_global_pattern = re.compile('config system global[\s\w\-"]*?end')
        system_global = system_global_pattern.search(config).group()
        hostname_pattern = re.compile('set hostname')
        hostname = hostname_pattern.search(system_global)
        if hostname:
            return (max_score , True , "Hostname Set")
        else:
            return (0 , False ,"No Hostname Set, Please set a custom one!")

    #2.1.6 Ensure the latest firmware is installed (Manual)
    def check_firmware_latest(self,max_score,config):
        #get model 
        model_firmware_pattern = re.compile('#config-version=[\w\-.]*?:')
        model_firmware_string = model_firmware_pattern.search(config).group()
        model_pattern = re.compile('=\w*?-')
        firmware_pattern = re.compile('-[\d.]{2,6}-')
        model_string = model_pattern.search(model_firmware_string).group().replace("=","").replace("-","")
        firmware_string = firmware_pattern.search(model_firmware_string).group().replace("-","")

        #get firmware from website.
        payload = {"model":model_string}
        response = requests.post('https://docs.fortinet.com/upgrade-tool',data=payload)
        latest_firmware = response.json()['result']['available_to'][-1]
        print(f"Model:{model_string} Firmware:{firmware_string} Latest Firmware:{latest_firmware}")
        if firmware_string == latest_firmware:
            return (max_score , True , "Firmware is Latest")
        else:
            return (0 , False ,"Firmware is out of date!")
        #TODO: Make it so that the more out of date the less points

    #2.1.7 Disable USB Firmware and configuration installation (Manual)
    def check_usb_firmware_install_disabled(self,max_score,config):
        auto_install_settings_pattern = re.compile('config system auto-install[\w\s\-]*?end')
        auto_install_settings = auto_install_settings_pattern.search(config).group()
        auto_install_config_enable_pattern = re.compile('set auto-install-config enable')
        auto_install_image_enable_pattern = re.compile('set auto-install-image enable')
        score = max_score 
        reason = ""
        isPass = False
        if auto_install_config_enable_pattern.search(auto_install_settings):
            score -= max_score/2
            reason += "Auto install config from USB enabled, "
        if auto_install_image_enable_pattern.search(auto_install_settings):
            score -= max_score/2
            reason += "Auto install images from USB enabled, "
        if reason == "":
            reason = "USB Firmware Upload Disabled"
            isPass = True

        return (score , isPass , reason)

    def static_keys_tls(self,max_score,config):
        system_global_pattern = re.compile('config system global[\s\w\-"]*?end')
        system_global = system_global_pattern.search(config).group()
        ssl_static_keys_disabled_pattern = re.compile('set ssl-static-key-ciphers disable')
        ssl_static_keys_disabled = ssl_static_keys_disabled_pattern.search(system_global)
        if ssl_static_keys_disabled:
            score = max_score
            reason = "SSL Static key Ciphers is Disabled"
            isPass = True
        else:
            score = 0
            reason = "SSL Static key Ciphers is Enabled"
            isPass = False

        return (score , isPass , reason)

    #2.1.9 Enable Global Strong Encryption (Manual)
    def check_strong_crypto_enabled(self,max_score,config):
        system_global_pattern = re.compile('config system global[\s\w\-"]*?end')
        system_global = system_global_pattern.search(config).group()
        strong_crypto_disabled_pattern = re.compile('set strong-crypto disable')
        strong_crypto_disabled = strong_crypto_disabled_pattern.search(system_global)
        if strong_crypto_disabled:
            return (0 , False , "Strong Crypto Disabled")
        else:
            return (max_score , True ,"Strong Crypto Enabled")
        
    #2.2.1 Ensure 'Password Policy' is enabled (Manual)
    def check_password_policy(self,max_score,config):
        password_policy_pattern = re.compile('config system password-policy[\w\s\-"]*?end')
        password_policy = password_policy_pattern.search(config).group()

        # default #################################
        # status              : enable 
        # apply-to            : admin-password 
        # minimum-length      : 8
        # min-lower-case-letter: 0
        # min-upper-case-letter: 0
        # min-non-alphanumeric: 0
        # min-number          : 0
        # min-change-characters: 0
        # expire-status       : disable 
        # reuse-password      : enable
        ###########################################
        
        #if setting is not defined it is the default
        enabled_pattern = re.compile('set status enable')

        apply_to_pattern = re.compile('set apply-to admin-password ipsec-preshared-key')
        minimum_length_pattern = re.compile('set minimum-length \d{1,3}')
        min_lower_case_letter_pattern = re.compile('set min-lower-case-letter \d{1,3}')
        min_upper_case_letter_pattern = re.compile('set min-upper-case-letter \d{1,3}')
        min_non_alphanumeric_pattern = re.compile('set min-non-alphanumeric \d{1,3}')
        min_number_pattern = re.compile('set min-number \d{1,3}')
        min_change_characters_pattern = re.compile('set min-change-characters \d{1,3}')
        expire_status_pattern = re.compile('set expire-status enable')
        reuse_password_pattern = re.compile('set reuse-password disable')
        reason = "Password Policy Disabled"
        isPass = False
        score = 0
        if enabled_pattern.search(password_policy):
            #its enabled
            score += max_score/10
            reason = "Password Policy Enabled"
            isPass = True
            apply_to = apply_to_pattern.search(password_policy)
            minimum_length = minimum_length_pattern.search(password_policy)
            min_lower_case_letter = min_lower_case_letter_pattern.search(password_policy)
            min_upper_case_letter = min_upper_case_letter_pattern.search(password_policy)
            min_non_alphanumeric = min_non_alphanumeric_pattern.search(password_policy)
            min_number = min_number_pattern.search(password_policy)
            min_change_characters = min_change_characters_pattern.search(password_policy)
            expire_status = expire_status_pattern.search(password_policy)
            reuse_password = reuse_password_pattern.search(password_policy)

            #fine tune Numbers below
            if apply_to:
                score += max_score/10
            if minimum_length:
                if 12 < int(minimum_length.group().split(" ")[-1]):
                    score += max_score/10
            if min_lower_case_letter:
                if 2 < int(min_lower_case_letter.group().split(" ")[-1]):
                    score += max_score/10
            if min_upper_case_letter:
                if 2 < int(min_upper_case_letter.group().split(" ")[-1]):
                    score += max_score/10
            if min_non_alphanumeric:
                if 2 < int(min_non_alphanumeric.group().split(" ")[-1]):
                    score += max_score/10
            if min_number:
                if 2 <= int(min_number.group().split(" ")[-1]):
                    score += max_score/10
            if min_change_characters:
                if 1 <= int(min_change_characters.group().split(" ")[-1]):
                    score += max_score/10
            if expire_status:
                score += max_score/10
            if reuse_password:
                score += max_score/10
        else:
            score = 0
            reason = "Password Policy Disabled"
            isPass = False
        return (score, isPass, reason)

    #2.2.2 Ensure administrator password retries and lockout time are configured (Manual)
    def check_lockout_policy(self,max_score,config):
        #if not configured its
        # admin-lockout-duration: 60
        # admin-lockout-threshold: 3
        system_global_pattern = re.compile('config system global[\s\w\-"]*?end')
        admin_lockout_duration_pattern = re.compile('set admin-lockout-threshold \d{1,3}')
        admin_lockout_threshold_pattern = re.compile('set admin-lockout-duration \d{1,5}')
        system_global = system_global_pattern.search(config).group()
        admin_lockout_duration = admin_lockout_duration_pattern.search(system_global)
        admin_lockout_threshold = admin_lockout_threshold_pattern.search(system_global)
        score = 0
        reason = ""
        isPass = True
        if admin_lockout_duration:
            if 120 < int(admin_lockout_duration.group().split(" ")[-1]):
                score += max_score/2
                reason = "Admin Lockout Duration < 120, "


        if admin_lockout_threshold:
            if 10 > int(admin_lockout_threshold.group().split(" ")[-1]):
                score += max_score/2
                reason = "Admin Failed password > 10, "

        if reason == "":
            isPass = False
            reason = "Admin lockout Policy is misconfigured"

        return (score, isPass, reason)

    #2.3.1 Ensure SNMP agent is disabled (Manual)
    #2.3.2 Ensure only SNMPv3 is enabled (Manual)
    def check_insecure_snmp_disabled(self,max_score,config):
        #general SNMP checks
        system_snmp_sysinfo_pattern = re.compile('config system snmp sysinfo[\s\w\-."]*?\nend')
        snmp_enable_pattern = re.compile('set status enable')
        #v2 Checks
        system_snmp_community_pattern = re.compile('config system snmp community[\s\w\-."]*?\nend')
        snmpv2_community_pattern = re.compile('edit[\s\w\-."]*?\n    next')
        snmpv2_community_disabled_pattern = re.compile('set status disable')
        #v3 Checks
        system_snmp_user_pattern = re.compile('config system snmp user[\s\w\-."]*?\nend')
        snmpv3_user_pattern = re.compile('edit[\s\w\-.\/"=+]*?\n    next')
        security_level_pattern = re.compile('set security-level [\w\-]*?')
        isPass = False
        reason = ""
        score = 0
        #snmpv3 user options no-auth-no-priv (nothing) or auth-no-priv + 2.5 auth-priv + 5
        system_snmp_sysinfo = system_snmp_sysinfo_pattern.search(config).group()
        if snmp_enable_pattern.search(system_snmp_sysinfo):
            #snmp is enabled
            #is SNMPV2 enabled
            system_snmp_community = system_snmp_community_pattern.search(config)
            if system_snmp_community:
                snmpv2_communities = snmpv2_community_pattern.findall(system_snmp_community.group())
                #are there commuities setup?
                if snmpv2_communities:
                    for v2_community in snmpv2_communities:
                        #is community enabled?
                        if snmpv2_community_disabled_pattern.search(v2_community):
                            #community is disabled SECURE
                            score += (max_score/2)/len(snmpv2_communities)
                            reason += "SNMP Communities disabled"
                else:
                    score += max_score/2
                    reason += "SNMP 1/2 disabled"
            #is SNMPv3 enabled
            system_snmp_user = system_snmp_user_pattern.search(config)
            if system_snmp_user:
            #is snmpv3 configured securely
                snmpv3_users = snmpv3_user_pattern.findall(system_snmp_user.group())
                #are users configured
                if snmpv3_users:
                    print(snmpv3_users)
                    for snmp_user in snmpv3_users:
                        #what is security Level set to 
                        security_level = security_level_pattern.search(snmp_user)
                        if security_level:
                            sec_lvl_value = security_level.group().split(" ")[-1]
                            print(sec_lvl_value)
                            if sec_lvl_value == "auth-priv":
                                score += max_score/2
                                reason += "SNMP v3 Auth and Priv"
                            if sec_lvl_value == "auth-no-priv":
                                score += max_score/4
                                reason += "SNMP v3 no Encryption"
                else:
                    score += max_score/2
        else:
            #snmp is not enabled at all
            score = max_score
            reason = "SNMP Disabled"

        if score == max_score:
            reason = "SNMP Secured"
            isPass = True
        return (score, isPass, reason)

    #TODO: 2.4.1 Ensure default 'admin' password is changed (Manual)

    #2.4.2 Ensure all the login accounts having specific trusted hosts enabled (Manual)
    def check_admin_trusted_hosts_configured(self,max_score,config):
        system_admin_pattern = re.compile('config system admin[\s\w\-"&.+=]*?\nend')
        admin_pattern = re.compile('edit["\-.+=\s\w]*?\n    next')
        trusted_host_pattern = re.compile('set trusthost\d{1,2}[0-9. ]{10,40}\n')

        admin_settings = system_admin_pattern.search(config).group()
        admins = admin_pattern.findall(admin_settings)
        score = max_score
        isPass = False
        reason = ""

        points_per_user = max_score / len(admins)
        for admin in admins:
            trusted_hosts = trusted_host_pattern.findall(admin)
            if len(trusted_hosts) > 0:
                print(trusted_hosts)
            else:
                reason += "trusted hosts not configured for an admin, "
                score -= points_per_user
        
        if reason == "":
            reason = "Trusted Hosts configured on all Admins"
            isPass = True

        return (score, isPass, reason)

    #2.4.4 Ensure idle timeout time is configured (Manual)
    def check_idle_timeout_configured(self,max_score,config):
        #if admintimeout exists and is higher then 15 no points
        #if it doesnt exist it is 5 
        system_global_pattern = re.compile('config system global[\s\w\-"]*?end')
        admin_timeout_pattern = re.compile('set admintimeout \d{1,3}')

        sys_global_settings = system_global_pattern.search(config).group()
        admin_timeout = admin_timeout_pattern.search(sys_global_settings)
        if admin_timeout:
            timeout_value = int(admin_timeout.group().split(" ")[-1])
        else:
            # default time out value if not specified
            timeout_value = 5

        if timeout_value > 15:
            return (0 , False ,"Timeout Value is too High, more than 15 min")
        else:
            return (max_score , True , "Time out value is less than 15 min")

    #2.4.5 Ensure only encrypted access channels are enabled (Manual)
    def check_encrypted_managment_only(self,max_score,config):
        system_interface_pattern = re.compile('config system interface[\s\w\-".]*?end')
        interface_pattern = re.compile('edit["\-.+=\s\w]*?\n    next')
        allowaccess_pattern = re.compile('set allowaccess [\w ]*?\n')
        insecure_mgmt_methods = ['http','telnet']

        interface_settings = system_interface_pattern.search(config).group()
        interfaces = interface_pattern.findall(interface_settings)

        if len(interfaces) > 0:
            score = max_score
            points_per_int = max_score / len(interfaces)
            for interface in interfaces:
                is_secure = True
                allowaccess = allowaccess_pattern.search(interface)
                if allowaccess:
                    allowed_mgmt_methods = allowaccess.group().replace("\n","").split(" ")
                    for method in insecure_mgmt_methods:
                        if method in allowed_mgmt_methods:
                            is_secure = False
                if not is_secure:
                    score -= points_per_int
            return (score , False ,"Some Interfaces allow Unecrypted management methods")
        else:
            return (max_score , True , "Only encrypted managment is allowed on all interfaces")
        #bad values http,telnet

    #2.5.1 Ensure High Availability Configuration (Manual
    def check_ha_configured(self,max_score,config):
        system_ha_pattern = re.compile('config system ha[\s\w\-"&.+=]*?end')
        ha_settings = system_ha_pattern.search(config).group()
        ha_int_pat = re.compile('set hbdev')
        ha_group_pat = re.compile('set group-name')
        ha_mode_pat = re.compile('set mode')
        #based on the settings below existing we can guess if HA is configured
        confidence = 0
        if ha_int_pat.search(ha_settings):
            confidence += 1
        if ha_group_pat.search(ha_settings):
            confidence += 1
        if ha_mode_pat.search(ha_settings):
            confidence += 1

        if confidence >= 2:
            return (max_score , True , "HA is configured")
        else:
            return (0 , False ,"HA is not configured")
            

    #2.5.2 Ensure "Monitor Interfaces" for High Availability Devices is Enabled (Manual)
    def check_ha_mon_iface(self,max_score,config):
        system_ha_pattern = re.compile('config system ha[\s\w\-"&.+=]*?end')
        ha_settings = system_ha_pattern.search(config).group()
        ha_mon_iface = re.compile('set monitor')
        if ha_mon_iface.search(ha_settings):
            return (max_score , True , "HA monitored interfaces are configured")
        else:
            return (0 , False ,"HA monitored interfaces are not configured")



    #2.5.3 Ensure HA Reserved Management Interface is Configured (Manual)
    def check_ha_mgmt_iface(self,max_score,config):
        system_ha_pattern = re.compile('config system ha[\s\w\-"&.+=]*?end')
        ha_settings = system_ha_pattern.search(config).group()
        ha_mgmt_enabled_pattern = re.compile('set ha-mgmt-status enable')
        ha_mgmt_iface_settings_pattern = re.compile('config ha-mgmt-interfaces')
        ifaces_pattern = re.compile('edit["\-.+=\s\w]*?\n    next')

        if ha_mgmt_enabled_pattern.search(ha_settings):
            ha_mgmt_iface_settings = ha_mgmt_iface_settings_pattern.search(ha_settings)
            if ha_mgmt_iface_settings:
                ifaces = ifaces_pattern.search(ha_mgmt_iface_settings.group())
                if ifaces > 0:
                    return (max_score , True , "HA Reserved Managment interfaces are configured")
        
        return (0 , False ,"HA Reserved Management interfaces are not configured")
    #TODO: 3.1 Ensure that unused policies are reviewed regularly (Manual)


    #3.2 Ensure that policies do not use "ALL" as Service (Manual)
    def no_all_services_policies(self,max_score,config):
        firewall_policy_pattern = re.compile('config firewall policy[\s\w\-"&.+=()]*?end')
        firewall_policies = firewall_policy_pattern.search(config).group()
        policy_pattern = re.compile('edit[\s\w\-"&.+=()]*?\n    next')
        service_all_pattern = re.compile('set service "ALL"\n')

        policies = policy_pattern.findall(firewall_policies)
        points_per_policy = max_score/len(policies)
        score = max_score
        reason = ""
        isPass = False
        bad_policy_list = []
        for policy in policies:
            if service_all_pattern.search(policy):
                score -= points_per_policy
                bad_policy_list.append(policy.split('"')[1])
                reason = f"{bad_policy_list} policies use service object 'all' "
        #TODO validate this works properly
        if reason == "":
            isPass = True
            reason = "No Policies use Service Object all"
        
        score = round(score,1)
        return (score,isPass,reason)



    #4.1.1 Detect Botnet Connections (Manual)
    def detect_botnet_connections(self,max_score,config):
        #get all policies, 
        firewall_policies_pattern = re.compile('config firewall policy[\s\w\-\"&.+=()/^]*?end\nconfig')
        firewall_policies = firewall_policies_pattern.search(config).group()
        policy_pattern = re.compile('edit[\s\w\-"&.+=()]*?\n    next')
        policies = policy_pattern.findall(firewall_policies)

        #system interfaces
        system_interface_pattern = re.compile('config system interface[\s\w\-\"&.+=()/^]*?end\nconfig')
        system_interface = system_interface_pattern.search(config).group()
        interface_pattern = re.compile('edit[\s\w\-"&.+=()]*?\n    next')
        interfaces = interface_pattern.findall(system_interface)
        is_wan_pattern = re.compile('set role wan')

        #sdwan
        system_sdwan_pattern = re.compile('config system sdwan[\s\w\-\"&.+=()^]*?end\nconfig')
        system_sdwan = system_sdwan_pattern.search(config).group()
        sdwan_zones_pattern = re.compile('config zone[\s\w\-\"&.+=()^]*?end')
        sdwan_zones = sdwan_zones_pattern.search(system_sdwan).group()
        zone_pattern = re.compile('edit[\s\w\-"&.+=()]*?       next')
        zones = zone_pattern.findall(sdwan_zones)

        #get all ips sensor profiles
        ips_sensors_config_pattern = re.compile('config ips sensor[\s\w\-\"&.+=()\/^]*?end\nconfig')
        ips_sensors_config = ips_sensors_config_pattern.search(config).group()
        sensor_pattern = re.compile('edit[\s\w\-"&.+=()\/]*?\n    next')
        sensors = sensor_pattern.findall(ips_sensors_config)
        is_botnet_blocked_pattern = re.compile('set scan-botnet-connections block')


        outbound_interfaces = []
        ips_sensors_blocking_botnet = []
        points_per_policy = max_score/len(policies)
        bad_policy_list = []
        score = max_score
        reason = ""
        isPass = False


        for sensor in sensors:
            if is_botnet_blocked_pattern.search(sensor):
                sensor_name = sensor.split('"')[1]
                ips_sensors_blocking_botnet.append(sensor_name)

        for interface in interfaces:
            if is_wan_pattern.search(interface):
                interface_name = interface.split('"')[1]
                outbound_interfaces.append(interface_name)

        for zone in zones:
            zone_name = zone.split('"')[1]
            outbound_interfaces.append(zone_name)

        
        for policy in policies:
            outbound_policy = False
            blocking_botnet = False
            for outbound_interface in outbound_interfaces:
                is_outbound_policy = re.compile(f'set dstintf "{outbound_interface}"')
                if is_outbound_policy.search(policy):
                    outbound_policy = True
            
            if outbound_policy:
                for ips_sensor in ips_sensors_blocking_botnet:
                    is_using_blocking_ips_sensor = re.compile(f'set ips-sensor "{ips_sensor}"')
                    if is_using_blocking_ips_sensor.search(policy):
                        blocking_botnet = True

                if not blocking_botnet:
                    bad_policy_list.append(policy.split('"')[1])
                    score -= points_per_policy
                    reason = f"{bad_policy_list} outbound policies don't have an IPS sensor Applied that block botnet connections."

        if reason == "":
            isPass = True
            reason = "All outbound Polices block botnets"

        return (score,isPass,reason)
                


    #4.2.1 Ensure Antivirus Definition Push Updates are Configured (Manual)
    def av_push_updates(self,max_score,config):
        av_update_config_pattern = re.compile('config system autoupdate schedule[\s\w\-"&.+=()]*?end')
        av_update_config = av_update_config_pattern.search(config)
        
        if av_update_config:
            status_disable_pattern = re.compile('set status disable')
            status_disable = status_disable_pattern.search(av_update_config.group())
            if status_disable:
                return (0 , False , "AV updates disabled") 

            
        return (max_score , True , "AV updates enabled")


    #4.2.2 Apply Antivirus Security Profile to Policies (Manual)
    def av_all_policies(self,max_score,config):
        firewall_policies_pattern = re.compile('config firewall policy[\s\w\-\"&.+=()/^]*?end\nconfig')
        firewall_policies = firewall_policies_pattern.search(config).group()
        policy_pattern = re.compile('edit[\s\w\-"&.+=()]*?\n    next')
        policies = policy_pattern.findall(firewall_policies)
        points_per_policy = max_score/len(policies)
        av_set_on_policy_pattern = re.compile('set av-profile')
        reason = ""
        isPass = False
        score = max_score
        bad_policy_list = []

        for policy in policies:
                if not av_set_on_policy_pattern.search(policy):
                    score -= points_per_policy
                    bad_policy_list.append(policy.split('"')[1])
                    reason = f"{bad_policy_list} Policies don't have AV applied"


        #TODO validate this works properly
        if reason == "":
            isPass = True
            reason = "All polices have AV applied"

        return (score , isPass , reason)



    def dns_block_botnet(self,max_score,config):
        #get all policies, 
        firewall_policies_pattern = re.compile('config firewall policy[\s\w\-\"&.+=()/^]*?end\nconfig')
        firewall_policies = firewall_policies_pattern.search(config).group()
        policy_pattern = re.compile('edit[\s\w\-"&.+=()]*?\n    next')
        policies = policy_pattern.findall(firewall_policies)

        #system interfaces
        system_interface_pattern = re.compile('config system interface[\s\w\-\"&.+=()/^]*?end\nconfig')
        system_interface = system_interface_pattern.search(config).group()
        interface_pattern = re.compile('edit[\s\w\-"&.+=()]*?\n    next')
        interfaces = interface_pattern.findall(system_interface)
        is_wan_pattern = re.compile('set role wan')

        #sdwan
        system_sdwan_pattern = re.compile('config system sdwan[\s\w\-\"&.+=()^]*?end\nconfig')
        system_sdwan = system_sdwan_pattern.search(config).group()
        sdwan_zones_pattern = re.compile('config zone[\s\w\-\"&.+=()^]*?end')
        sdwan_zones = sdwan_zones_pattern.search(system_sdwan).group()
        zone_pattern = re.compile('edit[\s\w\-"&.+=()]*?       next')
        zones = zone_pattern.findall(sdwan_zones)

        #get all dns profiles
        dnsfilters_config_pattern = re.compile('config dnsfilter profile[\s\w\-\"&.+=()\/^]*?end\nconfig')
        dnsfilters_config = dnsfilters_config_pattern.search(config).group()
        dnsfilter_pattern = re.compile('edit[\s\w\-"&.+=()\/]*?\n    next')
        dnsfilters = dnsfilter_pattern.findall(dnsfilters_config)
        is_botnet_blocked_pattern = re.compile('set block-botnet enable')


        outbound_interfaces = []
        dnsfilter_profiles_blocking_botnet = []
        points_per_policy = max_score/len(policies)
        bad_policy_list = []
        score = max_score
        reason = ""
        isPass = False


        for dnsfilter in dnsfilters:
            if is_botnet_blocked_pattern.search(dnsfilter):
                dnsfilter_name = dnsfilter.split('"')[1]
                dnsfilter_profiles_blocking_botnet.append(dnsfilter_name)

        for interface in interfaces:
            if is_wan_pattern.search(interface):
                interface_name = interface.split('"')[1]
                outbound_interfaces.append(interface_name)

        for zone in zones:
            zone_name = zone.split('"')[1]
            outbound_interfaces.append(zone_name)

        
        for policy in policies:
            outbound_policy = False
            blocking_botnet = False
            for outbound_interface in outbound_interfaces:
                is_outbound_policy = re.compile(f'set dstintf "{outbound_interface}"')
                if is_outbound_policy.search(policy):
                    outbound_policy = True
            
            if outbound_policy:
                for dnsfilter_profile in dnsfilter_profiles_blocking_botnet:
                    is_using_blocking_dnsfilter_profile = re.compile(f'set dnsfilter-profile "{dnsfilter_profile}"')
                    if is_using_blocking_dnsfilter_profile.search(policy):
                        blocking_botnet = True

                if not blocking_botnet:
                    bad_policy_list.append(policy.split('"')[1])
                    score -= points_per_policy
                    reason = f"{bad_policy_list} outbound policies don't have an DNS filter Applied that block botnet connections."
                    

        if reason == "":
            isPass = True
            reason = "All outbound Polices block botnets by DNS"

        return (score,isPass,reason) 


    #5.1.1 Enable Compromised Host Quarantine (Manual) (requires EMS + FAZ)
    def auto_quarntine_host_enabled(self,max_score,config):
        system_automation_stitch_pattern = re.compile('config system automation-stitch[\s\w\-\"&.+=()\/^]*?end\nconfig')
        system_automation_stitch = system_automation_stitch_pattern.search(config).group()
        quarantine_host_rule_pattern = re.compile('edit "Compromised Host Quarantine"[\s\w\-"&.+=()]*?\n    next')
        quarantine_host_rule = quarantine_host_rule_pattern.search(system_automation_stitch).group()
        is_status_enabled_pattern = re.compile('set status enable')

        if is_status_enabled_pattern.search(quarantine_host_rule):
            return (max_score , True , "Compromised Host Automation Quarantine Rule is enabled.")
        else:
            return (0 , False , "Compromised Host Automation Quarantine Rule is Disabled.")


    #5.2.1.1 Ensure Security Fabric is Configured (Manual)
    def security_fabric_configured(self,max_score,config):
        system_csf_pattern = re.compile('config system csf[\s\w\-\"&.+=()\/^]*?end\nconfig')
        system_csf = system_csf_pattern.search(config).group()
        is_status_enabled_pattern = re.compile('set status enable')
        is_name_configured_pattern = re.compile('set group-name')

        isPass = False
        reason = ""
        score = max_score

        if not is_status_enabled_pattern.search(system_csf):
            score =- max_score/2
            reason += "Security Fabric is Disabled, "

        if not is_name_configured_pattern.search(system_csf):
            score =- max_score/2
            reason += "Security Fabric is not configured"
            
        if reason == "":
            isPass = True
            reason = "Security Fabric Enabled and configured"

        return (score , isPass , reason)

    #6.1.2 Enable Limited TLS Versions for SSL VPN (Manual)
    def ssl_vpn_ciphers_limited(self,max_score,config):
        #is SSL VPN portal setup ?
        ssl_settings_pattern = re.compile('config vpn ssl settings[\s\w\-\"&.+=()\/^]*?end\nconfig')
        ssl_settings = ssl_settings_pattern.search(config).group()
        is_status_enabled_pattern = re.compile('set status enable')
        bad_tls_versions = ["tls1-0","tls1-1"]

        if is_status_enabled_pattern.search(ssl_settings):
            for tls_ver in bad_tls_versions:
                is_tls_version_low_pattern = re.compile("set ssl-min-proto-ver {tls_ver}")
                if is_tls_version_low_pattern.search(ssl_settings):
                    return (0 , False , "SSLVPN is Enabled and configured to older non-secure versions of TLS/SSL")
            return (max_score , True , "SSLVPN is Enabled and configured to use tls 1.2 and 1.3 only")
        else:
            return (max_score , True , "SSLVPN is disabled.")

    #7.1 Configuring the maximum login attempts and lockout period (Manual)
    def user_lockout(self,max_score,config):
        user_settings_pattern = re.compile('config user setting[\s\w\-\"&.+=()\/^]*?end\nconfig')
        user_settings = user_settings_pattern.search(config).group()

        user_lockout_threshorld_pattern = re.compile('auth-lockout-threshold \d*?')
        user_lockout_duration_pattern = re.compile('auth-lockout-duration \d*?')
        user_lockout_threshorld = user_lockout_threshorld_pattern.search(user_settings)
        user_lockout_duration = user_lockout_duration_pattern.search(user_settings)

        # defaults
        # auth-lockout-threshold: 3
        # auth-lockout-duration: 0

        if user_lockout_threshorld:
            threshold = user_lockout_threshorld.group().split(" ")[1]
        else:
            threshold = 3

        if user_lockout_duration:
            duration = user_lockout_duration.group().split(" ")[1]
        else:
            duration = 0


        isPass = False
        reason = ""
        score = max_score

        if threshold > 5:
            score -= max_score/2
            reason += "User Password retry threshold is too high, "
        
        if duration == 0:
            score -= max_score/2
            reason += "Failed user login lockout duration disabled, "
        elif duration < 300:
            score -= max_score/2
            reason += "Failed user login lockout duration is too low, "
        

        if reason == "":
            isPass = True
            reason = "User Lockout Policy properly configured"

        return (score , isPass , reason)

    #8.1.1 Enable Event Logging (Manual)
    def enable_event_logging_score(self,max_score,config):
        log_settings_pattern = re.compile('config log eventfilter[\s\w\-\"&.+=()\/^]*?end\nconfig')
        is_event_log_disabled = re.compile('set event disable')
        log_settings = log_settings_pattern.search(config)

        if log_settings:
            if is_event_log_disabled.search(log_settings.group()):
                return (0 , False , "Event logging is Disabled.")
                
        return (max_score , True , "Event logging is Enabled.")

    #8.2.1 Encrypt Log Transmission to FortiAnalyzer / FortiManager (Manual)
    def encrypted_log_transmission(self,max_score,config):
        faz_log_settings_pattern = re.compile('config log fortianalyzer setting[\s\w\-\"&.+=()\/^]*?end\nconfig')
        faz_log_settings = faz_log_settings_pattern.search(config).group()

        is_enc_agl_high_med_pattern = re.compile('set enc-algorithm high-medium')
        is_enc_agl_low_pattern = re.compile('set enc-algorithm low')

        
        if is_enc_agl_high_med_pattern.search(faz_log_settings) == "high":
            return (max_score/2 , False , "Log Transmission to Fortigate and Fortianalyzer encryption is set to high-medium.")
        elif is_enc_agl_low_pattern.search(faz_log_settings):
            return (0 , False , "Log Transmission to Fortigate and Fortianalyzer encryption is set to low.")
        else:
            return (max_score , True , "Log Transmission to Fortigate and Fortianalyzer encryption is set to high.")
checks = config_checks()
class manual_checks:
    def __init__(self):
        pass
    #6.1.1 Apply a Trusted Signed Certificate for VPN Portal (Manual)
    def vpn_portal_trusted_cert(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isCertTrusted = input("Is the certificate applied to your SSL VPN portal trusted publicly or by your SSLVPN Clients? This can be verified by connecting via SSLVPN or webportal mode and if no Cert message pops up it is trusted.\n(Y/N)")
            if isCertTrusted.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"The certificate applied to your SSL VPN portal is trusted publicly or by your SSLVPN Clients")
            elif isCertTrusted.capitalize() == "N":
                isInputValid = True
                return (0,False,"The certificate applied to your SSL VPN portal is untrusted publicly or by your SSLVPN Clients")
            else:
                isInputValid = False
    #2.4.1 Ensure default 'admin' password is changed
    def default_admin_password(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isPasswordChanged = input("Was the defualt administrator 'admin' password changed?\n(Y/N)")
            if isPasswordChanged.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"Default admin password was changed")
            elif isPasswordChanged.capitalize() == "N":
                isInputValid = True
                return (0,False,"Default admin password was not changed")
            else:
                isInputValid = False



    def admin_trusted_hosts(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isTrustedHostConfigured = input("Do all administrators have Trusted hosts configured?\n(Y/N)")
            if isTrustedHostConfigured.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"All administrators have Trusted hosts configured")
            elif isTrustedHostConfigured.capitalize() == "N":
                isInputValid = True
                return (0,False,"Not all administrators have Trusted hosts configured")
            else:
                isInputValid = False

    def verify_admin_privileges(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isTrustedHostConfigured = input("Do all administrators with different privileges have the correct profiles assigned?\nAre all Profiles' persmissions following the rule of Least Privilage?\n(Y/N)")
            if isTrustedHostConfigured.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"Administator Profiles and Permissions Configured Correctly With Least Privliaged in Mind.")
            elif isTrustedHostConfigured.capitalize() == "N":
                isInputValid = True
                return (0,False,"Administator profiles and permissions are not configured correctly and/or do no adhere to the prinicple of Least Privliage.")
            else:
                isInputValid = False

    def regular_review(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isPoliciesReviewedRegularly = input("Are firewall policies reviewed regularly ?\n(Y/N)")
            if isPoliciesReviewedRegularly.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"Firewall policies are not reviewed regularly.")
            elif isPoliciesReviewedRegularly.capitalize() == "N":
                isInputValid = True
                return (0,False,"Firewall policies are reviewed regularly.")
            else:
                isInputValid = False

    def unique_names(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isUniquelyNamed = input("Are all firewall policies uniquely named?\n(Y/N)")
            if isUniquelyNamed.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"Firewall policies are not uniquely named.")
            elif isUniquelyNamed.capitalize() == "N":
                isInputValid = True
                return (0,False,"Firewall policies are uniquely named.")
            else:
                isInputValid = False


    def no_unused_policies(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isNoUnusedPolicies = input("Based on the total hits and recent hits, hit count for each firewall policy are they all in use?\n(Y/N)")
            if isNoUnusedPolicies.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"No unused firewall policies exist.")
            elif isNoUnusedPolicies.capitalize() == "N":
                isInputValid = True
                return (0,False,"Unused firewall policies exist.")
            else:
                isInputValid = False



    def central_logging_configured(self,max_score, config=""):
        isInputValid = False
        while not isInputValid:
            isCentralLoggingConfigured = input("Is central logging configured via FortiAnalyzer, Forticloud, or Syslog?\n(Y/N)")
            if isCentralLoggingConfigured.capitalize() == "Y":
                isInputValid = True
                return (max_score,True,"Central logging is in use.")
            elif isCentralLoggingConfigured.capitalize() == "N":
                isInputValid = True
                return (0,False,"Central logging is in not use.")
            else:
                isInputValid = False
manual_checks = manual_checks()

##check defs
checks = [
    {
        "check_ref_number":"1.1",
        "check_name":"Ensure DNS server is configured",
        "max_score":10,
        "api_check_function":api_checks.dns_configured,
        "config_check_function":checks.check_dns_configured
    },
    {
        "check_ref_number":"1.2",
        "check_name":"Ensure intra-zone traffic is not always allowed",
        "max_score":10,
        "api_check_function": api_checks.deny_intrazone,
        "config_check_function":checks.check_intrazone_denied
    },
    {
        "check_ref_number":"2.1.1",
        "check_name":"Ensure 'Pre-Login Banner' is set",
        "max_score":10,
        "api_check_function":api_checks.pre_login_banners_set,
        "config_check_function":checks.check_prelogin_banner,
    },
    {
        "check_ref_number":"2.1.2",
        "check_name":"Ensure 'Post-Login-Banner' is set",
        "max_score":10,
        "api_check_function":api_checks.post_login_banners_set,
        "config_check_function":checks.check_postlogin_banner,
    },
    {
        "check_ref_number":"2.1.3",
        "check_name":"Ensure timezone is properly configured",
        "max_score":10,
        "api_check_function":api_checks.timezone_set,
        "config_check_function":checks.check_timezone_configured
    },
    {
        "check_ref_number":"2.1.4",
        "check_name":"Ensure correct system time is configured through NTP",
        "max_score":10,
        "api_check_function":api_checks.ntp_configured,
        "config_check_function":checks.check_ntp_configured
    },
    {
        "check_ref_number":"2.1.5",
        "check_name":"Ensure hostname is set",
        "max_score":10,
        "api_check_function":api_checks.hostname_set,
        "config_check_function":checks.check_hostname_configured
    },
    {
        "check_ref_number":"2.1.6",
        "check_name":"Ensure the latest firmware is installed",
        "max_score":10,
        "api_check_function":api_checks.latest_firmware_installed,
        "config_check_function":checks.check_firmware_latest
    },
    {
        "check_ref_number":"2.1.7",
        "check_name":"Disable USB Firmware and configuration installation",
        "max_score":10,
        "api_check_function":api_checks.usb_fw_disabled,
        "config_check_function":checks.check_usb_firmware_install_disabled
    },
    {
        "check_ref_number":"2.1.8",
        "check_name":"Disable static keys for TLS",
        "max_score":10,
        "api_check_function":api_checks.static_keys_tls,
        "config_check_function":checks.static_keys_tls
    },
    {
        "check_ref_number":"2.1.9",
        "check_name":"Enable Global Strong Encryption",
        "max_score":10,
        "api_check_function":api_checks.strong_encryption,
        "config_check_function":checks.check_strong_crypto_enabled
    },
    {
        "check_ref_number":"2.2.1",
        "check_name":"Ensure 'Password Policy' is enabled",
        "max_score":10,
        "api_check_function":api_checks.password_policy,
        "config_check_function":checks.check_password_policy
    },
    {
        "check_ref_number":"2.2.2",
        "check_name":"Ensure administrator password retries and lockout time are configured",
        "max_score":10,
        "api_check_function":api_checks.admin_lockout,
        "config_check_function":checks.check_lockout_policy
    },
    {
        "check_ref_number":"2.3.1",
        "check_name":"Ensure SNMP agent is disabled",
        "max_score":10,
        "api_check_function":api_checks.snmp_agentv12_disabled,
        "config_check_function":checks.check_insecure_snmp_disabled
    },
    {
        "check_ref_number":"2.3.2",
        "check_name":"Ensure only SNMPv3 is enabled",
        "max_score":10,
        "api_check_function":api_checks.snmpv3_user,
        "config_check_function":checks.check_insecure_snmp_disabled
    },
    {
        "check_ref_number":"2.4.1",
        "check_name":"Ensure default 'admin' password is changed",
        "max_score":10,
        "api_check_function":manual_checks.default_admin_password,
        "config_check_function":manual_checks.default_admin_password,
    },
    {
        "check_ref_number":"2.4.2",
        "check_name":"Ensure all the login accounts having specific trusted hosts enabled",
        "max_score":10,
        "api_check_function":manual_checks.admin_trusted_hosts,
        "config_check_function":checks.check_admin_trusted_hosts_configured
    },
    {
        "check_ref_number":"2.4.3",
        "check_name":"Ensure admin accounts with different privileges having their correct profiles assigned",
        "max_score":10,
        "api_check_function":manual_checks.verify_admin_privileges,
        "config_check_function":manual_checks.verify_admin_privileges
    },
    {
        "check_ref_number":"2.4.4",
        "check_name":"Ensure idle timeout time is configured",
        "max_score":10,
        "api_check_function":api_checks.idle_timeout,
        "config_check_function":checks.check_idle_timeout_configured
    },
    {
        "check_ref_number":"2.4.5",
        "check_name":"Ensure only encrypted access channels are enabled",
        "max_score":10,
        "api_check_function":api_checks.encrypted_access,
        "config_check_function":checks.check_encrypted_managment_only
    },
    {
        "check_ref_number":"2.5.1",
        "check_name":"Ensure High Availability Configuration",
        "max_score":10,
        "api_check_function":api_checks.ha_setup,
        "config_check_function":checks.check_ha_configured
    },
    {
        "check_ref_number":"2.5.2",
        "check_name":"Ensure 'Monitor Interfaces' for High Availability Devices is Enabled",
        "max_score":10,
        "api_check_function":api_checks.ha_monitored_interfaces,
        "config_check_function":checks.check_ha_mon_iface
    },
    {
        "check_ref_number":"2.5.3",
        "check_name":"Ensure HA Reserved Management Interface is Configured",
        "max_score":10,
        "api_check_function":api_checks.ha_reserved_mgmt_int,
        "config_check_function":checks.check_ha_mgmt_iface
    },
    {
        "check_ref_number":"3.1",
        "check_name":"Ensure that unused policies are reviewed regularly",
        "max_score":10,
        "api_check_function":manual_checks.regular_review,
        "config_check_function":manual_checks.regular_review
    },
    {
        "check_ref_number":"3.2",
        "check_name":"Ensure that policies do not use 'ALL' as Service",
        "max_score":10,
        "api_check_function":api_checks.service_all_policies,
        "config_check_function":checks.no_all_services_policies
    },
    {
        "check_ref_number":"3.3",
        "check_name":"Ensure Policies are Uniquely Named",
        "max_score":10,
        "api_check_function":manual_checks.unique_names,
        "config_check_function":manual_checks.unique_names
    },
    {
        "check_ref_number":"3.4",
        "check_name":"Ensure there are no Unused Policies",
        "max_score":10,
        "api_check_function":api_checks.no_unused_policies,
        "config_check_function":manual_checks.no_unused_policies
    },
    {
        "check_ref_number":"4.1.1",
        "check_name":"Detect Botnet Connections Enabled",
        "max_score":10,
        "api_check_function":api_checks.detect_botnet_connections,
        "config_check_function":checks.detect_botnet_connections
    },
    {
        "check_ref_number":"4.2.1",
        "check_name":"Ensure Antivirus Definition Push Updates are Configured",
        "max_score":10,
        "api_check_function":api_checks.av_push_updates,
        "config_check_function":checks.av_push_updates
    },
    {
        "check_ref_number":"4.2.2",
        "check_name":"Apply Antivirus Security Profile to Policies",
        "max_score":10,
        "api_check_function":api_checks.av_all_policies,
        "config_check_function":checks.av_all_policies
    },
    {
        "check_ref_number":"4.3.1",
        "check_name":"Enable Botnet C&C Domain Blocking DNS Filter",
        "max_score":10,
        "api_check_function":api_checks.dns_block_cnc_score,
        "config_check_function":checks.dns_block_botnet
    },
    {
        "check_ref_number":"5.1.1",
        "check_name":"Enable Compromised Host Quarantine",
        "max_score":10,
        "api_check_function":api_checks.auto_quarntine_host_enabled,
        "config_check_function":checks.auto_quarntine_host_enabled
    },
    {
        "check_ref_number":"5.2.1",
        "check_name":"Ensure Security Fabric is Configured",
        "max_score":10,
        "api_check_function":api_checks.security_fabric_configured,
        "config_check_function":checks.security_fabric_configured
    },
    {
        "check_ref_number":"6.1.1",
        "check_name":"Apply a Trusted Signed Certificate for VPN Portal",
        "max_score":10,
        "api_check_function":manual_checks.vpn_portal_trusted_cert,
        "config_check_function":manual_checks.vpn_portal_trusted_cert
    },
    {
        "check_ref_number":"6.1.2",
        "check_name":"Enable Limited TLS Versions for SSL VPN",
        "max_score":10,
        "api_check_function":api_checks.ssl_vpn_ciphers_limited,
        "config_check_function":checks.ssl_vpn_ciphers_limited
    },
    {
        "check_ref_number":"7.1",
        "check_name":"Configuring the maximum login attempts and lockout period",
        "max_score":10,
        "api_check_function":api_checks.user_lockout,
        "config_check_function":checks.user_lockout
    },
    {
        "check_ref_number":"8.1.1",
        "check_name":"Enable Event Logging",
        "max_score":10,
        "api_check_function":api_checks.enable_event_logging_score,
        "config_check_function":checks.enable_event_logging_score
    },
    {
        "check_ref_number":"8.2.1",
        "check_name":"Encrypt Log Transmission to FortiAnalyzer / FortiManager",
        "max_score":10,
        "api_check_function":api_checks.encrypted_log_transmission,
        "config_check_function":checks.encrypted_log_transmission
    },
    {
        "check_ref_number":"8.3.1",
        "check_name":"Centralized Logging and Reporting",
        "max_score":10,
        "api_check_function":api_checks.central_logging_configured,
        "config_check_function":manual_checks.central_logging_configured
    }
]



def run_check(check_function, check_ref_number:str, check_name:str, max_score:float = 10 ):
    (score , isPass , reason) = check_function(max_score)
    if isPass:
        pass_status = "PASS"
    else:
        pass_status = "FAIL"
    score_percent = round(score/max_score * 25)
    inverse_percent = 25 - score_percent
    score_bar = f"[{'#'*score_percent}{'.'*inverse_percent}] {score}/{max_score}"
    print(f"| {check_ref_number} {check_name} | {score_bar} {pass_status} | {reason} |")

    return (score , max_score, reason, isPass)

def run_config_check(check_function, config, check_ref_number:str, check_name:str, max_score:float = 10 ):
    (score , isPass , reason) = check_function(max_score,config)
    if isPass:
        pass_status = "PASS"
    else:
        pass_status = "FAIL"
    score_percent = round(score/max_score * 25)
    inverse_percent = 25 - score_percent
    score_bar = f"[{'#'*score_percent}{'.'*inverse_percent}] {score}/{max_score}"
    print(f"| {check_ref_number} {check_name} | {score_bar} {pass_status} | {reason} |")

    return (score , max_score, reason, isPass)

#api Method
def query_api(url,key):
    
    total_score = 0
    possible_score = 0
    data = pandas.DataFrame(columns=["ref","name","score","possible","pass","reason"])
    data["pass"]=data["pass"].astype(bool)
    for check in checks:
        possible_score += check["max_score"]
        (score , max_score, reason, isPass) = run_check(check["api_check_function"],check["check_ref_number"],check["check_name"],check["max_score"])
        total_score += score
        data = pandas.concat([data, pandas.DataFrame.from_records([{
            "ref":check["check_ref_number"],
            "name":check["check_name"],
            "score":score,
            "possible":max_score,
            "pass":isPass,
            "reason":reason
        }])])
    return (total_score , possible_score, data)
#Total Score

#Run Checks on Config Report Pass Fail
def query_config(config):
    total_score = 0
    possible_score = 0
    data = pandas.DataFrame(columns=["ref","name","score","possible","pass","reason"])
    data["pass"]=data["pass"].astype(bool)
    for check in checks:
        possible_score += check["max_score"]
        (score , max_score, reason, isPass) = run_config_check(check["config_check_function"],config,check["check_ref_number"],check["check_name"],check["max_score"])
        total_score += score
        data = pandas.concat([data, pandas.DataFrame.from_records([{
            "ref":check["check_ref_number"],
            "name":check["check_name"],
            "score":score,
            "possible":max_score,
            "pass":isPass,
            "reason":reason
        }])])
    return (total_score , possible_score, data)



if __name__ == "__main__":
    #param stuff
    #init parser
    parser = argparse.ArgumentParser(usage="\nconfig file: main.py -i fortigate_backup.conf -o result.csv\nAPI method: main.py -u https://10.10.10.10/ -k 1a1a1a1a-2b2b2b2b2-3c3c3c3c3 -o result.csv")
    #defined name args
    parser.add_argument('-i','--infile',help="Specify the path of the config file for the fortigate that you want to scan ",type=pathlib.Path)
    parser.add_argument('-u','--url',help="Specify the URL to that exposed if checking the fortigate using the API", type=str)
    parser.add_argument('-k','--key',help="Specify the API key to use if checking the fortigate using the API", type=str)
    parser.add_argument('-o','--outfile',help="Specify the path of the CSV file to dump the results to. if not specified you will only see results in the terminal.",type=pathlib.Path)
    #parse parameters
    args = parser.parse_args()
    #config file mode or API mode
    if args.url is not None and args.key is not None:
        api = FortiGateAPI()
        (total_score , possible_score, data) = query_api(args.url,args.key)
        print(f"Final Score: {total_score:.2f} out of {possible_score} points")
        print(data)
    elif args.infile is not None:
        config = read_regular_config(args.infile)
        (total_score , possible_score, data) = query_config(config)
        print(f"Final Score: {total_score:.2f} out of {possible_score} points")
        print(data)
    else:
        print("please use either [--infile] to use the config file method or both [--key] and [--url] to use the API method")
    #output nonsense
    if args.outfile is not None:
        print("add data to csv!")
        data.to_csv(args.outfile,index=False)
        