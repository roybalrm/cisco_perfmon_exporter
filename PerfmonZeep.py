"""Export Cisco PerfMon API counters to Prometheus."""

# This file is part of cisco_perfmon_exporter.

# cisco_perfmon_exporter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# cisco_perfmon_exporter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with cisco_perfmon_exporter. If not, see <https://www.gnu.org/licenses/>.

import click
from zeep import Client
from zeep.transports import Transport
import yaml
from prometheus_client import Gauge

perfmon_data = Gauge('cisco_perfmon_total',
                         'Cisco PerfMon counter value',
                         ['name', 'instance'])

cucm_unreachable = Counter('cucm_unreachable_total',
                               'Total times CUCM was unreachable')

# Section 1
def get_perfmon_data(config):
    """Get PerfMon data from CUCM."""
    for server in config['perfmon']:
        server_url = f"https://{server['server_address']}:{server['server_port']}/perfmonservice/services/PerfmonPort"
        try:
            transport = Transport(timeout=10, operation_timeout=10)
            client = Client(server_url, transport=transport)
            response = client.service.getPerfmonData(server['username'], server['password'], server['server_name'])
        except Exception as err:
            cucm_unreachable.inc()
            print(f"Error connecting to {server['server_name']}: {err}")
            continue
# Section 2
        for counter in response:
            name = counter.Name
            instance = counter.Instance
            value = counter.Value
            perfmon_data.labels(name=name, instance=instance).set(float(value))

@click.command()
@click.option('--config', '-c', help='Exporter configuration file.')
@click.option('--debug/--no-debug', default=False, help='Enable/disable debug output.')
def start_exporter(config, debug):
    """Start the Cisco PerfMon exporter."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    with open(config) as f:
        config = yaml.safe_load(f)

    get_perfmon_data(config)

if __name__ == '__main__':
    start_exporter()
