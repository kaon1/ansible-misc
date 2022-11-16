### Ad Hoc script run once to fix an architectural problem I originally implemented. 
### Initially I populated all PRTG devices by Domain Name (DNS)
### Later on, I decided to monitor everything by IP (not DNS)

# This python script alters all existing PRTG devices to monitor by IP instead of DNS Hostname
# Populate IP from NETBOX. Calls Netbox API to grab IP of the device name
# Call PRTG API '/api/setobjectproperty.htm?' to make the desired change
# Kaon Thana 10-12-2021
from time import sleep

import requests
import os


# vars
device_name = ""
device_ip = ""

# Get passwords and keys from OS ENV
# To set this in OS, enter the command: 'export NETBOX_TOKEN='
netbox_token = os.getenv('NETBOX_TOKEN')
prtg_token = os.getenv('PRTG_TOKEN')

# URLs to hit for netbox API call
netbox_api_url = "https://<URL>/api/dcim/devices/"

# PRTG URLs for API Call
prtg_base_url = "https://prtg<URL>"
prtg_end_url = "&username=api_user_networking&passhash={}".format(prtg_token)
prtg_all_devices = "/api/table.json?content=devices&output=json&columns=objid,probe,group,device,host,downsens,partialdownsens,downacksens,upsens,warnsens,pausedsens,unusualsens,undefinedsens&count=1000"

def main():     # main function
    # main function runs to update prtg
    prtg_update_device_with_ip()

def prtg_update_device_with_ip():

    global device_name
    global prtg_base_url
    global prtg_end_url
    global prtg_all_devices
    global device_ip
    prtg_api_call = prtg_base_url + prtg_all_devices + prtg_end_url

    # prtg api call to grab all devices
    prtg_request_get_all_devices = requests.get(prtg_api_call, verify=False)

    for device in prtg_request_get_all_devices.json()['devices']:
        if device['device'] != "Core Device" and device['device'] != "Probe Device" and device['device'] != "do_not_delete_for_cloning":
            device_ip = netbox_grab_ip_from_device_name(device['device'])
            prtg_update_url = "/api/setobjectproperty.htm?id=" + str(device['objid']) + "&name=host&value=" + device_ip
            prtg_complete_api = prtg_base_url + prtg_update_url + prtg_end_url
            print("PRTG CURRENT VALUE: " + str(device['objid']) + " --> " + device['device'] + " --> " + device['host'])
            prtg_response = requests.get(prtg_complete_api, verify=False)
            print(prtg_response)
            print("PRTG NEW VALUE: " + str(device['objid']) + " --> " + device['device'] + " --> " + device_ip)
            sleep(.2)

def netbox_grab_ip_from_device_name(device_name):
    # params for requests
    netbox_params = {'name': "{}".format(device_name)}
    netbox_headers = {'Authorization': "Token {}".format(netbox_token)}

    # netbox request to grab host info filter by device NAME
    netbox_request =requests.get(netbox_api_url, params=netbox_params, headers=netbox_headers, verify=False)

    # store result in json variable
    netbox_result = netbox_request.json()

    # retrieve IP without MASK
    ip_mask = netbox_result['results'][0]['primary_ip']['address']
    device_ip = ip_mask.split('/')[0]

    return device_ip

if __name__ == "__main__":
    main()