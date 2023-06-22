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

import base64
import re
import sys

import click
from lxml import etree
import yaml
from zope.interface import implementer

from prometheus_client import Gauge
from prometheus_client.twisted import MetricsResource

from twisted.internet import endpoints
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.defer import DeferredQueue
from twisted.internet.defer import succeed
from twisted.internet.protocol import Protocol
from twisted.internet.ssl import CertificateOptions
from twisted.logger import Logger
from twisted.logger import globalLogBeginner
from twisted.logger import textFileLogObserver
from twisted.python.url import URL
from twisted.web.client import Agent
from twisted.web.client import BrowserLikePolicyForHTTPS
from twisted.web.client import Headers
from twisted.web.client import HTTPConnectionPool
from twisted.web.client import ResponseDone
from twisted.web.client import _HTTP11ClientFactory
from twisted.web.iweb import IBodyProducer
from twisted.web.iweb import IPolicyForHTTPS
from twisted.web.resource import Resource
from twisted.web.server import Site
# ... (remaining imports and constants)

@implementer(IBodyProducer)
class Utf8Producer(object):
    """UTF-8 producer."""

    log = Logger()

    def __init__(self, body):
        """Initalize."""
        try:
            self.body = body.encode('utf-8')
        except UnicodeEncodeError as err:
            self.log.error("Unable to encode body to UTF-8: {err}", err=err)
        self.length = len(self.body)

    def startProducing(self, consumer):
        """State producing."""
        try:
            consumer.write(self.body)
        except Exception as err:
            self.log.error("Unable to write to consumer: {err}", err=err)
        return succeed(None)

    def pauseProducing(self):
        """Pause producing."""
        pass

    def stopProducing(self):
        """Stop producing."""
        pass


@implementer(IBodyProducer)
class BytesProducer(object):
    """Bytes producer."""

    log = Logger()

    def __init__(self, body):
        """Initalize."""
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        """State producing."""
        try:
            consumer.write(self.body)
        except Exception as err:
            self.log.error("Unable to write to consumer: {err}", err=err)
        return succeed(None)

    def pauseProducing(self):
        """Pause producing."""
        pass

    def stopProducing(self):
        """Stop producing."""
        pass


class Gather(Protocol):
    """Gather data and log results."""

    log = Logger()

    def __init__(self, finished=None, debug=True):
        """Initialize."""
        self.buffer = []
        self.finished = finished
        self.debug = debug
        self.cucm_connection_errors = Counter('cucm_connection_errors_total',
                                             'Total CUCM connection errors')
        self.cucm_unreachable = Counter('cucm_unreachable_total',
                                       'Total times CUCM was unreachable')

    def dataReceived(self, data):
        """Receeive a chunk of data."""
        self.buffer.append(data)
    def connectionLost(self, reason):
        """Remote connection lost."""
        if not isinstance(reason.value, ResponseDone):
            self.log.error('Connection lost: {reason}', reason=reason)
            if reason.check(ConnectionError):
                self.cucm_connection_errors.inc()
                self.log.debug('Retrying connection to CUCM...')
                retry_d = self.connect_to_cucm()
            else:
                self.log.error("Unhandled error: {reason}", reason=reason)
        if self.finished:
            self.finished.callback(b''.join(self.buffer))

    def connect_to_cucm(self):
        """Connect to CUCM."""
        if not self.cucm_url:
            self.log.error("No CUCM URL specified.")
            return succeed(None)
        self.log.debug('Connecting to {url}...', url=self.cucm_url)
        headers = Headers({'Content-Type': ['text/xml; charset="utf-8"']})
        return self.agent.request(b'GET', self.cucm_url.encode(), headers)

    def get_perfmon_data(self):
        """Get PerfMon counter data from CUCM."""
        if not self.cucm_url:
            self.log.error("No CUCM URL specified.")
            return succeed(None)
        self.log.debug('Getting PerfMon data from {url}...', url=self.cucm_url)
        body = self.perfmon_request.encode('utf-8')
        headers = Headers({'Content-Type': ['text/xml; charset="utf-8"'],
                           'SOAPAction': ['"getPerfmonData"']})
        return self.agent.request(b'POST', self.cucm_url.encode(), headers,
                                  Utf8Producer(body))

@implementer(IPolicyForHTTPS)
@implementer(IBodyProducer)
class PerfmonRequest(object):
    """PerfMon SOAP request."""

    soap_template = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<SOAP-ENV:Body>
<ns1:getPerfmonData xmlns:ns1="http://www.cisco.com/AXL/API/10.5">
<ns1:name>{name}</ns1:name>
</ns1:getPerfmonData>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
    def __init__(self, perfmon_name):
        """Initialize."""
        self.perfmon_name = perfmon_name
        self.body = self.soap_template.format(name=perfmon_name)
        self.length = len(self.body)

    def startProducing(self, consumer):
        """Start producing."""
        consumer.write(self.body.encode('utf-8'))
        return succeed(None)

    def pauseProducing(self):
        """Pause producing."""
        pass

    def stopProducing(self):
        """Stop producing."""
        pass

@click.command()
@click.option('--config', '-c', help='Exporter configuration file.')
@click.option('--debug/--no-debug', default=False, help='Enable/disable debug output.')
def start_exporter(config, debug):
    """Start the Cisco PerfMon exporter."""
    log_observer = textFileLogObserver(sys.stdout)
    globalLogBeginner.beginLoggingTo([log_observer])

    if debug:
        log_observer.emit = log_observer.debug

    with open(config) as f:
        config = yaml.safe_load(f)

    agent = Agent(reactor, contextFactory=CertificateOptions())
    agent._pool = HTTPConnectionPool(reactor, persistent=True)
    agent.policy = PerfmonPolicy(config['cucm']['good_domains'])

    perfmon_data = Gauge('cisco_perfmon_total',
                         'Cisco PerfMon counter value',
                         ['name', 'instance'])

    cucm_unreachable = Counter('cucm_unreachable_total',
                               'Total times CUCM was unreachable')

    queue = DeferredQueue()
    gatherer = Gather(queue, debug=debug)
    gatherer.cucm_url = URL.fromText(config['cucm']['url'])
    gatherer.perfmon_request = PerfmonRequest(config['perfmon']['name'])
    gatherer.agent = agent

    metrics = MetricsResource(registry=registry)
    root = Resource()
    root.putChild(b'metrics', metrics)
    site = Site(root)
    endpoint = endpoints.TCP4ServerEndpoint(reactor, config['exporter']['port'])
    endpoint.listen(site)

    def process_perfmon_data(data):
        """Process PerfMon data."""
        if not data:
            cucm_unreachable.inc()
            return

        root = etree.fromstring(data)
        for counter in root.findall('{http://www.cisco.com/AXL/API/10.5}Counter'):
            name = counter.find('{http://www.cisco.com/AXL/API/10.5}Name').text
            instance = counter.find('{http://www.cisco.com/AXL/API/10.5}Instance').text
            value = counter.find('{http://www.cisco.com/AXL/API/10.5}Value').text
            perfmon_data.labels(name=name, instance=instance).set(float(value))

    def get_perfmon_data():
        """Get PerfMon data from CUCM."""
        gatherer.get_perfmon_data().addCallback(process_perfmon_data)
        reactor.callLater(config['perfmon']['interval'], get_perfmon_data)

    get_perfmon_data()
    reactor.run()

if __name__ == '__main__':
    start_exporter()
