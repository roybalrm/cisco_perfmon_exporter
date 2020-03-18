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

namespaces = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
              'soap': 'http://schemas.cisco.com/ast/soap'}
soapenv = '{{{}}}'.format(namespaces['soapenv'])
soap = '{{{}}}'.format(namespaces['soap'])


@implementer(IBodyProducer)
class Utf8Producer(object):
    """UTF-8 producer."""

    log = Logger()

    def __init__(self, body):
        """Initalize."""
        self.body = body.encode('utf-8')
        self.length = len(self.body)

    def startProducing(self, consumer):  # noqa N802
        """State producing."""
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):  # noqa N802
        """Pause producing."""
        pass

    def stopProducing(self):  # noqa N802
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

    def startProducing(self, consumer):  # noqa N802
        """State producing."""
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):  # noqa N802
        """Pause producing."""
        pass

    def stopProducing(self):  # noqa N802
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

    def dataReceived(self, data):  # noqa: N802
        """Receeive a chunk of data."""
        self.buffer.append(data)

    def connectionLost(self, reason):  # noqa: N802
        """Remote connection lost."""
        if not isinstance(reason.value, ResponseDone):
            self.log.error('connection lost: {reason:}', reason=reason)

        buffer = b''.join(self.buffer)

        if self.debug:
            self.log.debug('{buffer:}', buffer=buffer)

        if self.finished is not None:
            self.finished.callback(buffer)


@implementer(IPolicyForHTTPS)
class WhitelistContextFactory(object):
    def __init__(self, good_domains=None):
        """
        :param good_domains: List of domains. The URLs must be in bytes
        """
        if not good_domains:
            self.good_domains = []
        else:
            self.good_domains = good_domains

        # by default, handle requests like a browser would
        self.default_policy = BrowserLikePolicyForHTTPS()

    def creatorForNetloc(self, hostname, port):
        # check if the hostname is in the the whitelist, otherwise return the default policy
        if hostname in self.good_domains:
            return CertificateOptions(verify=False)
        return self.default_policy.creatorForNetloc(hostname, port)


class QuietHTTP11ClientFactory(_HTTP11ClientFactory):
    """Less noisy version of _HTTP11ClientFactory."""

    noisy = False


class RateLimitAgent(object):
    def __init__(self):
        self.pool = HTTPConnectionPool(reactor, persistent=True)
        self.pool.maxPersistentPerHost = 4
        self.pool._factory = QuietHTTP11ClientFactory
        self.contextFactory = WhitelistContextFactory()
        self.agent = Agent(reactor, pool=self.pool, contextFactory=self.contextFactory)
        self.queue = DeferredQueue()
        self.getRequest()

    def request(self, method, url, headers, body):
        finished = Deferred()
        self.queue.put((finished, method, url, headers, body))
        return finished

    def getRequest(self):
        d = self.queue.get()
        d.addCallback(self.gotRequest)

    def gotRequest(self, request):
        finished, method, url, headers, body = request

        d = self.agent.request(method, bytes(url), headers, body)
        d.addCallback(self.cbRequest, finished)
        d.addErrback(self.ebRequest, finished)

    def cbRequest(self, response, finished):
        finished.callback(response)
        reactor.callLater(1.3, self.getRequest)

    def ebRequest(self, failure, finished):
        finished.errback(failure)
        reactor.callLater(1.3, self.getRequest)


class ServerPoller(object):
    log = Logger()

    counter_re = re.compile(r'\A\\\\(.*)\\(.*?)(?:\((.*)\))?\\(.*)\Z')

    def __init__(self, perfmon, server_name, server_address, server_port, username, password, verify, included_objects):
        self.perfmon = perfmon
        self.server_name = server_name
        self.server_address = server_address
        self.server_port = server_port
        self.username = username
        self.password = password
        self.verify = verify
        self.included_objects = included_objects

        self.authorization = base64.b64encode('{}:{}'.format(self.username, self.password).encode('utf-8'))
        self.headers = Headers({b'Content-Type': [b'text/xml; charset=utf-8'],
                                b'Authorization': [b'Basic ' + self.authorization]})

        self.agent = RateLimitAgent()
        if not self.verify:
            self.agent.contextFactory.good_domains.append(self.server_address.encode('utf-8'))

        self.url = URL.fromText('https://{server_address:}:{server_port:}/perfmonservice2/services/PerfmonService?wsdl'.format(server_address=server_address,
                                                                                                                               server_port=server_port))

        self.openSession()

    def openSession(self):
        body = Utf8Producer("""<?xml version='1.0' encoding='UTF-8'?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">
        <soapenv:Header/>
        <soapenv:Body>
            <soap:perfmonOpenSession/>
        </soapenv:Body>
        </soapenv:Envelope>
        """)

        d = self.agent.request(b'POST',
                               self.url,
                               self.headers,
                               body)
        d.addCallback(self.gotOpenSessionResponse)

    def gotOpenSessionResponse(self, response):
        if response.code == 200:
            finished = Deferred()
            finished.addCallback(self.gotOpenSessionResult)
            g = Gather(finished, debug=False)
            response.deliverBody(g)

    def gotOpenSessionResult(self, result):
        root = etree.fromstring(result)
        self.session_handle = str(root.xpath('//soap:perfmonOpenSessionReturn/text()', namespaces=namespaces)[0])
        self.log.info('Opened session {session_handle:} on server {server_address:}',
                      session_handle=self.session_handle,
                      server_address=self.server_address)

        self.listCounters()
        self.collectSessionData()

    def collectSessionData(self):
        body = Utf8Producer("""<?xml version='1.0' encoding='utf-8'?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">
        <soapenv:Header/>
        <soapenv:Body>
            <soap:perfmonCollectSessionData>
                <soap:SessionHandle>{session_handle:}</soap:SessionHandle>
            </soap:perfmonCollectSessionData>
        </soapenv:Body>
        </soapenv:Envelope>
        """.format(session_handle=self.session_handle))

        d = self.agent.request(b'POST',
                               self.url,
                               self.headers,
                               body)
        d.addCallback(self.collectSessionDataResponse)
        d.addErrback(self.collectSessionDataError)

    def collectSessionDataError(self, failure):
        self.log.failure('Problem collecting session data!', failure=failure)
        reactor.callLater(30, self.collectSessionData)

    def collectSessionDataResponse(self, response):
        if response.code == 200:
            finished = Deferred()
            finished.addCallback(self.collectSessionDataResult)
            g = Gather(finished, debug=False)
            response.deliverBody(g)

        else:
            finished = Deferred()
            finished.addCallback(self.collectSessionDataResultError, response.code)
            g = Gather(finished)
            response.deliverBody(g)

    def collectSessionDataResult(self, result):
        root = etree.fromstring(result)

        for data in root.xpath('//soap:perfmonCollectSessionDataReturn', namespaces=namespaces):
            name = str(data.xpath('soap:Name/text()', namespaces=namespaces)[0])
            match = self.counter_re.match(name)
            if not match:
                continue
            host = match.group(1)
            object_name = match.group(2)
            instance_name = match.group(3)
            counter_name = match.group(4)

            value = int(data.xpath('soap:Value/text()', namespaces=namespaces)[0])
            cstatus = int(data.xpath('soap:CStatus/text()', namespaces=namespaces)[0])

            if cstatus not in [0, 1]:
                reactor.stop()

            self.perfmon.labels(host=host, object=object_name, instance=instance_name, counter=counter_name).set(value)

        reactor.callLater(30.0, self.collectSessionData)

    def collectSessionDataResultError(self, result, code):
        reactor.callLater(30, self.collectSessionData)

    def listCounters(self):
        body = Utf8Producer("""<?xml version='1.0' encoding='UTF-8'?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">
        <soapenv:Header/>
        <soapenv:Body>
            <soap:perfmonListCounter>
                <soap:Host>{host:}</soap:Host>
            </soap:perfmonListCounter>
        </soapenv:Body>
        </soapenv:Envelope>
        """.format(host=self.server_name))

        d = self.agent.request(b'POST',
                               self.url,
                               self.headers,
                               body)
        d.addCallback(self.listCountersResponse)
        d.addErrback(self.listCountersError)

    def listCountersError(self, failure):
        self.log.failure('Problem listing counters!', failure=failure)

    def listCountersResponse(self, response):
        if response.code == 200:
            finished = Deferred()
            finished.addCallback(self.listCountersResult)
            g = Gather(finished, debug=False)
            response.deliverBody(g)

    def listCountersResult(self, result):
        root = etree.fromstring(result)

        for counters in root.xpath('//soap:perfmonListCounterReturn', namespaces=namespaces):
            object_name = str(counters.xpath('soap:Name/text()', namespaces=namespaces)[0])
            if object_name not in self.included_objects:
                self.log.warn('Skipping object "{object_name:}" because it was not included in the config.', object_name=object_name)
                continue

            multi_instance = str(counters.xpath('soap:MultiInstance/text()', namespaces=namespaces)[0])
            if multi_instance == 'true':
                self.listInstances(counters, object_name)
                continue

            xml_envelope = etree.Element(soapenv + 'Envelope', nsmap=namespaces)
            etree.SubElement(xml_envelope, soapenv + 'Header')
            xml_body = etree.SubElement(xml_envelope, soapenv + 'Body')
            xml_perfmon_add_counter = etree.SubElement(xml_body, soap + 'perfmonAddCounter')
            xml_session_handle = etree.SubElement(xml_perfmon_add_counter, soap + 'SessionHandle')
            xml_session_handle.text = self.session_handle
            xml_array_of_counter = etree.SubElement(xml_perfmon_add_counter, soap + 'ArrayOfCounter')

            for counter_name in map(str, counters.xpath('//soap:item/soap:Name/text()', namespaces=namespaces)):
                # print(object_name, counter_name)
                xml_counter = etree.SubElement(xml_array_of_counter, soap + 'Counter')
                xml_name = etree.SubElement(xml_counter, soap + 'Name')
                xml_name.text = "\\\\{server_name:}\\{object_name:}\\{counter_name:}".format(server_name=self.server_name,
                                                                                             object_name=object_name,
                                                                                             counter_name=counter_name)

            body = BytesProducer(etree.tostring(xml_envelope, xml_declaration=True, encoding='utf-8'))
            d = self.agent.request(b'POST',
                                   self.url,
                                   self.headers,
                                   body)
            d.addCallback(self.addCounterResponse, body)

    def listInstances(self, counters, object_name):
        body = Utf8Producer("""<?xml version='1.0' encoding='UTF-8'?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">
            <soapenv:Header/>
            <soapenv:Body>
                <soap:perfmonListInstance>
                    <soap:Host>{host:}</soap:Host>
                    <soap:Object>{object:}</soap:Object>
                </soap:perfmonListInstance>
            </soapenv:Body>
        </soapenv:Envelope>
        """.format(host=self.server_name,
                   object=object_name))
        d = self.agent.request(b'POST', self.url, self.headers, body)
        d.addCallback(self.listInstancesResponse, counters, object_name)
        d.addErrback(self.listInstancesError, counters, object_name)

    def listInstancesError(self, failure, counters, object_name):
        self.log.failure('Problem listing instances for {object_name:}', object_name=object_name, failure=failure)

    def listInstancesResponse(self, response, counters, object_name):
        if response.code == 200:
            finished = Deferred()
            finished.addCallback(self.listInstancesResult, counters, object_name)
            g = Gather(finished, debug=False)
            response.deliverBody(g)

    def listInstancesResult(self, result, counters, object_name):
        instances = etree.fromstring(result)

        xml_envelope = etree.Element(soapenv + 'Envelope', nsmap=namespaces)
        etree.SubElement(xml_envelope, soapenv + 'Header')
        xml_body = etree.SubElement(xml_envelope, soapenv + 'Body')
        xml_perfmon_add_counter = etree.SubElement(xml_body, soap + 'perfmonAddCounter')
        xml_session_handle = etree.SubElement(xml_perfmon_add_counter, soap + 'SessionHandle')
        xml_session_handle.text = self.session_handle
        xml_array_of_counter = etree.SubElement(xml_perfmon_add_counter, soap + 'ArrayOfCounter')

        count = 0
        for counter_name in map(str, counters.xpath('//soap:item/soap:Name/text()', namespaces=namespaces)):
            # print(object_name, counter_name)
            for instance_name in map(str, instances.xpath('//soap:perfmonListInstanceReturn/soap:Name/text()', namespaces=namespaces)):
                count += 1
                self.log.debug('{server_address:}, {server_name:}, {object_name:}, {instance_name:}, {counter_name:}',
                               server_address=self.server_address,
                               server_name=self.server_name,
                               object_name=object_name,
                               instance_name=instance_name,
                               counter_name=counter_name)
                xml_counter = etree.SubElement(xml_array_of_counter, soap + 'Counter')
                xml_name = etree.SubElement(xml_counter, soap + 'Name')
                xml_name.text = "\\\\{server_name:}\\{object_name:}({instance_name:})\\{counter_name:}".format(server_name=self.server_name,
                                                                                                               object_name=object_name,
                                                                                                               instance_name=instance_name,
                                                                                                               counter_name=counter_name)

        if count > 0:
            body = BytesProducer(etree.tostring(xml_envelope, xml_declaration=True, encoding='utf-8'))
            d = self.agent.request(b'POST',
                                   self.url,
                                   self.headers,
                                   body)
            d.addCallback(self.addCounterResponse, body)
        else:
            self.log.warn('{server_address:}, {server_name:}, {object_name:}: no instances',
                          server_address=self.server_address,
                          server_name=self.server_name,
                          object_name=object_name,)

    def addCounterResponse(self, response, body):
        if response.code == 500:
            finished = Deferred()
            finished.addCallback(self.addCounterResultError, response.code, body)
            g = Gather(finished, debug=False)
            response.deliverBody(g)

        else:
            finished = Deferred()
            finished.addCallback(self.addCounterResult, response.code, body)
            g = Gather(finished, debug=True)
            response.deliverBody(g)

    def addCounterResult(result, code, body):
        pass

    fault_string_re = re.compile(r'\A(.*): Error=(\d+) ErrorMsg=(.*)\Z')

    def addCounterResultError(self, result, code, body):
        root = etree.fromstring(result)
        # fault_code = str(root.xpath('//soapenv:Fault/faultcode/text()', namespaces=namespaces)[0])
        fault_string = str(root.xpath('//soapenv:Fault/faultstring/text()', namespaces=namespaces)[0])
        match = self.fault_string_re.match(fault_string)
        if match:
            if match.group(1) == 'Error found in Adding counters':
                self.log.warn('Couldn\'t add all requested counters:')
                counters = match.group(3).split(';')
                for counter in counters:
                    match = self.counter_re.match(counter)
                    if match:
                        server_name = match.group(1)
                        object_name = match.group(2)
                        instance_name = match.group(3)
                        counter_name = match.group(4)
                        self.log.warn('  {server_name:}, {object_name:}, {instance_name:}, {counter_name:}',
                                      server_name=server_name,
                                      object_name=object_name,
                                      instance_name=instance_name,
                                      counter_name=counter_name)

        else:
            self.log.error('Error: {code:} {text:}', code=code, text=result)
            self.log.error('Body: {body:}', body=body.body)
            reactor.stop()


class QuietSite(Site):
    """Less noisy version of Site."""

    noisy = False


@click.command()
@click.argument('configfile', type=click.File('rb'))
def main(configfile):
    config = yaml.safe_load(configfile)
    reactor.callWhenRunning(start, config)
    reactor.run()


def start(config):
    output = textFileLogObserver(sys.stderr)
    globalLogBeginner.beginLoggingTo([output])

    root = Resource()
    metrics = MetricsResource()
    root.putChild(b'metrics', metrics)
    site = QuietSite(root)

    endpoint = endpoints.serverFromString(reactor, 'tcp:{}'.format(config['prometheus']['http_port']))
    endpoint.listen(site)

    perfmon = Gauge('cisco_perfmon_counter', 'Cisco PerfMon API Counter', labelnames=('host', 'object', 'instance', 'counter'))

    for server in config['perfmon']:
        ServerPoller(perfmon,
                     server['server_name'],
                     server['server_address'],
                     server['server_port'],
                     server['username'],
                     server['password'],
                     server['verify'],
                     server['included_objects'])


if __name__ == '__main__':
    main()
