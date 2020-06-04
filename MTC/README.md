# Moving Target Controller (MTC)

**Controller for the Low Frequency NAS Subnets**

## Setup

1. Configure mtc.json and add it to the applications root directory

## Conf

| Parameter         | Description            | Type  |
| ----------------  |----------------------- | ----- |
| max_mapping_sliding_window | Keep old routes for n shuffling periods | Int |
| router | Settings for the connection to the Router | - |
| hostsv4 | List of NAS Hosts (Hosts which should be protected) - rIP  | List(String (IPv4)) |
| hostsv6 | List of NAS Hosts (Hosts which should be protected) - rIP | List(String (IPv6)) |
| gateway_mapping | Map of MTG and the connected MT rIP subnet (MTG IP, rIP Subnet) | Map(String(IP), String(IPSUbnet)) |
| subnetv4 | List of available vIP subnets (IPv4) | List(String(Ipv4 Subnet)) |
| subnetv6 | List of available vIP subnets (IPv6) | List(String(Ipv6 Subnet)) |
| urls | Map of URLs of the MTG REST APIs and the rIP Subnets they administrate | Map(URL, List(IP_Subnet)) |

### Router Setting

| Parameter         | Description            | Type  |
| ----------------  |----------------------- | ----- |
| ip | IP Address of the Router | String (IP) |
| username | Linux (SSH) username | String |
| password | Linux (SSH) password | String |