# Moving Target Gateway (MTG)

**Gateway for Network Address Shuffling (Low Frequency Shuffling, controlled by MT Controller) and Port Hopping**

## Setup

1. Dependencies:
  * Install Python3 or PyPy
  * Install additional dependencies for netfilterqueue: apt-get install build-essential python-dev libnetfilter-queue-dev iptables-persistent
  * Install packages of requirements.txt
2. Set PreRouting IPTable rules for IPv4 and IPv6. Forward every package to the queue (e.g. 1 = in = public interface, 2 = out = private interface). Examples: /conf/rules.v*.txt
Using PreRouting Rules, to route to link local or remote addresses after address manipulation. 
3. Enable IP Forwarding in /etc/sysctl.conf (net.ipv6.conf.all.forwarding=1, net.ipv4.ip_forward = 1)
4. Disable Reverse Path Filtering in /etc/sysctl.conf 
5. Set correct routes for vIP and rIP subnets
6. Add conf json file to root directory of MTG. Examples: /conf/*.json

Use Pypy for faster execution

## Conf

| Parameter         | Description            | Type  |
| ----------------  |----------------------- | ----- |
| debug_forward     | Dont translate or track connections, directly forward all the packages from public interface to private interface and vise vera | Bool |
| ph                | Setting for Port Hopping | - |
| nas               | Setting for Network Address Shuffling | - |
| file_logging      | Logging to File | Bool |
| debug_output      | Logging to Console | Bool |
| whitelist         | List of IP-Addresses or Subnets which should be directly forwarded without manipulation by PH or NAS | List of Strings (IP) |

### PH Settings

| Parameter         | Description            | Type  |
| ----------------  |----------------------- | ----- |
| activate          | Activate Port Hopping  | Bool |
| client         | Activate Port Hopping Client mode. (At MTPortGateways) | Bool |
| hopping_period     | Hopping Period of the PH Function in seconds | Int |
| max_buffer     | Number of precomputed hash values in buffer (will increase speed)| Int |
| keymap | PreSharedKeys for Source IP-Addresses | Map<IP, PSK> |
| ph_subnets_server | Subnets which are protected on the server side | List<Subnet> |


### NAS Settings

| Parameter         | Description            | Type  |
| ----------------  |----------------------- | ----- |
| activate          | Activate Network Address Shuffling  | Bool |
| tracking         | Settings for NAS Connection Tracking | - |
| receiver       | List of HighFrequency Data receivers (send data to a Gateway, which is responsible for DNS translation) | List of  Strings (URLs) |
| hopping_period | Hopping Period of the LF (Low Frequency) Controller in seconds | Int |
| rest_iface        | IP of the local REST Interface which is used to receive the subnet informations of the MTController           | String (IP) |

#### NAS Connection Tracking Settings

| Parameter         | Description            | Type  |
| ----------------  |----------------------- | ----- |
| track             | Enable Connection Tracking (required for all other options) | Bool |
| continue_all      | Allow all Connections to continue after HF Shuffling has been completed | Bool |
| dynamic_port_priority | Settings for Dynamic Port Priority | - |


##### NAS Dynamic Port Priority Settings
| Parameter         | Description            | Type  |
| ----------------  |----------------------- | ----- |
| continue             | List of Connections (based on the real destination/host ports) which should be allowed to continue after HF Shuffling | List(Int / Port) |
| priority      | Mapping of ports to priority class | Map(String (Port), String(Priority Class)) |
| priority_def | Definition of priority classes, how long should each class block the HF shuffeling process | Map(String(Priority Class), Int(Block)) |



