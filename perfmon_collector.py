from axltoolkit import UcmPerfMonToolkit
import yaml
import time

from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY


class PerfmonCollector(object):
    config = None
    collector_data = {}

    def __init__(self, config_file):
        with open(config_file, 'r') as yaml_file:
            self.config = yaml.safe_load(yaml_file)
            self.parse_config()

    def __del__(self):
        print("Closing Sessions")
        self.close_collection_sessions()

    def parse_config(self):
        if self.config is not None:
            print("parsing config")
            for cluster in self.config['clusters']:
                print(cluster)
                for server in cluster['servers']:
                    print(server)
                    if server['server_address'] not in self.collector_data:
                        self.collector_data[server['server_address']] = {
                            'perfmon_api': UcmPerfMonToolkit(cluster['username'], cluster['password'],
                                                             server['server_address'], cluster['verify']),
                            'counters': []
                        }

                    server_perfmon = self.collector_data[server['server_address']]['perfmon_api']
                    server_counter_list = server_perfmon.perfmonListCounter(server["server_name"])

                    for item in server['collect']:
                        if 'counters' not in item:
                            server_counter = server_counter_list[item['object']]
                            item['counters'] = server_counter['counters']

                        # If this is a multi-instance object and config does not specify specific instances
                        # then retreive the list of all instances

                        if 'instances' not in item and server_counter_list[item['object']]['multi_instance'] is True:
                            counter_instances = server_perfmon.perfmonListInstance(server["server_name"],
                                                                                   item["object"])
                            item['instances'] = counter_instances

                        for counter in item['counters']:
                            if 'instances' in item:
                                for instance in item['instances']:
                                    counter_string = f'\\\\{server["server_name"]}\\{item["object"]}({instance})\\{counter}'
                                    self.collector_data[server['server_address']]['counters'].append(counter_string)
                            else:
                                counter_string = f'\\\\{server["server_name"]}\\{item["object"]}\\{counter}'
                                self.collector_data[server['server_address']]['counters'].append(counter_string)

    def open_collection_sessions(self):
        for server in self.collector_data:
            perfmon = self.collector_data[server]['perfmon_api']
            counters = self.collector_data[server]['counters']

            session_handle = perfmon.perfmonOpenSession()
            # TODO: Error Checking if session handle is not retreived
            self.collector_data[server]['session_handle'] = session_handle

            perfmon.perfmonAddCounter(session_handle=session_handle, counters=counters)
            # TODO: Error Checking if error adding counters

    def close_collection_sessions(self):
        for server in self.collector_data:
            if 'session_handle' in self.collector_data[server]:
                session_handle = self.collector_data[server]['session_handle']
                perfmon = self.collector_data[server]['perfmon_api']

                perfmon.perfmonCloseSession(session_handle=session_handle)
                # TODO: Error Checking if error closing session

    def collect_data(self):
        collected_data = {}

        for server in self.collector_data:
            if 'session_handle' in self.collector_data[server]:
                session_handle = self.collector_data[server]['session_handle']
                perfmon = self.collector_data[server]['perfmon_api']

                result = perfmon.perfmonCollectSessionData(session_handle=session_handle)
                if result is not None:
                    for server in result:
                        collected_data[server] = result[server]
                else:
                    # TODO: Error Checking if collection fails - might need to deal with refreshing session
                    pass

        return collected_data


class PerfmonExporter(object):
    collector = None

    def __init__(self, collector):
        print("Init of PerfmonExporter")
        self.collector = collector

    def object_counter_to_metric_name(self, object_name, counter):
        return f'ciscoperfmon_{object_name.lower().replace(" ", "_").replace("%", "percent").replace("-", "_")}_{counter.lower().replace(" ", "_").replace("%", "percent").replace("-", "_")}'

    def collect(self):
        print("Collect in PerfMonExporter")
        result = self.collector.collect_data()

        # metrics = GaugeMetricFamily('cisco_perfmon_counter', 'Cisco PerfMon API Counter',
        #                             labels=('host', 'object', 'instance', 'counter'))

        metrics = {}

        for server, server_data in result.items():
            for perfmon_object, perfmon_object_data in server_data.items():
                if perfmon_object_data['multi_instance'] is True:
                    for instance, instance_data in perfmon_object_data['instances'].items():
                        for counter, value in instance_data.items():
                            metric_name = self.object_counter_to_metric_name(perfmon_object, counter)
                            if metric_name not in metrics:
                                metric = GaugeMetricFamily(metric_name, f'Cisco PerfMon API - Object: {perfmon_object}, Counter: {counter}',
                                        labels=('host', 'instance'))
                                metrics[metric_name] = metric
                            else:
                                metric = metrics[metric_name]
                            metric.add_metric([server, instance], value)
                else:
                    for counter, value in perfmon_object_data['counters'].items():
                        metric_name = self.object_counter_to_metric_name(perfmon_object, counter)
                        if metric_name not in metrics:
                            metric = GaugeMetricFamily(metric_name, f'Cisco PerfMon API - Object: {perfmon_object}, Counter: {counter}',
                                                       labels=['host'])
                            metrics[metric_name] = metric
                        else:
                            metric = metrics[metric_name]
                        metric.add_metric([server], value)

                        # metrics.add_metric([server, perfmon_object, '', counter], value)

        for name, item in metrics.items():
            yield item


if __name__ == "__main__":
    perfmon_collector = PerfmonCollector('perfmon.yaml')
    perfmon_collector.open_collection_sessions()
    REGISTRY.register(PerfmonExporter(perfmon_collector))
    start_http_server(9118)
    while True:
        time.sleep(30)

