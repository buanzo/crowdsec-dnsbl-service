#!/usr/bin/env python3
# Crowdsec-DNSBL-Server
# Author: Buanzo
# Uses pycrowdsec to get decisions for the queried IP - Requires a LocalAPI and a bouncer token
#
"""
Custom DNSBL server using Twisted
No upstream resolver.
"""

from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server
import os

from pycrowdsec.client import StreamClient

# cscli bouncers add dnsblservice then save the key to CROWDSEC_API_KEY envvar
csclient = StreamClient(api_key=os.environ["CROWDSEC_API_KEY"])
csclient.run()

from pprint import pprint

class CrowdSecDecisionsResolver(object):
    """
    This resolver only calculates responses for queries that match standard DNSBL requests such as
    Server will return 127.0.0.2 for an IP with a "ban" action on the crowdsec decisions list. NXDOMAIN for else.
    NOTE: You might want to return 127.0.0.3 for "captcha" action... need feedback.
    $ dig +short @DNSSERVER reversed_octets.DNSBLSERVER.net
    See https://www.spamhaus.org/faq/section/DNSBL%20Usage for more information (thank you Spamhaus!)
    """

    def _isValidIP(self, ip):
        """
        Checks if ip is indeed a valid IP address
        """
        return(True)  # TODO: make real :P

    def _ipFromQuery(self, query):  # FIX: duplicate code in _ValidDNSBLquery...
        _name = query.name.name.decode('utf8')
        _ip = '.'.join(_name.split('.')[0:4][::-1])
        return(_ip)

    def _validDNSBLquery(self, query):
        if query.type == dns.A:
            # We need to get the IP from query.name.name
            _name = query.name.name.decode('utf8')
            if _name.count('.') > 4:  # d.b.c.a.DNSBLZONE.hostname.net
                try:
                    _ip = '.'.join(_name.split('.')[0:4][::-1])
                except Exception as ex:
                    return(False)
                # We return a True/False decision if it is a valid IP
                return(self._isValidIP(_ip))
        return(False)

    def _getCrowdSecDecision(self, query):
        """
        Query CrowdSec decisions for the queried IP
        https://twistedmatrix.com/documents/16.5.0/names/howto/custom-server.html
        """
        _ip = self._ipFromQuery(query)
        action = csclient.get_action_for(_ip)
        return(action)

    def _doCrowdSecResponse(self, query):
        answer = dns.RRHeader(name=query.name.name,
                              payload=dns.Record_A(address=b'127.0.0.2'))
        answers = [answer]
        authority = []
        additional = []
        return answers, authority, additional

    def query(self, query, timeout=None):
        """
        Validate query, return error if invalid. Remember, this a DNSBL server for a DNSBL zone.
        """
        if self._validDNSBLquery(query) and self._getCrowdSecDecision(query) == "ban":
            return defer.succeed(self._doCrowdSecResponse(query))
        else:
            return defer.fail(error.DomainError())


def main():
    factory = server.DNSServerFactory(clients=[CrowdSecDecisionsResolver()])
    protocol = dns.DNSDatagramProtocol(controller=factory)
    reactor.listenUDP(53, protocol)
    reactor.listenTCP(53, factory)  # do we need this for DNSBL?
    reactor.run()

if __name__ == '__main__':
    main()
