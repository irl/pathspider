import pathspider.base
from pathspider.base import PluggableSpider
from pathspider.single import SingleSpider
from pathspider.chains.basic import BasicChain
from pathspider.chains.dscp import DSCPChain
from pathspider.chains.mss import MSSChain
from pathspider.chains.tcp import TCPChain
from pathspider.chains.tcpopt import TCPOptChain

class BlockPages(SingleSpider, PluggableSpider):

    name = "blockpages"
    description = "Web Block Pages"
    version = pathspider.base.__version__
    chains = [BasicChain, TCPChain, TCPOptChain, MSSChain, DSCPChain]
    connect_supported = ["http", "https"]

    def combine_flows(self, flows):
        conditions = []

        if not flows[0]['observed']:
            return ['pathspider.not_observed']

        conditions.append(self.combine_connectivity(flows[0]['tcp_connected']))

        if flows[0]['tcp_connected']:
            conditions.append('mss.option.local.value:' + str(flows[0]['mss_value_fwd']))
            if flows[0]['mss_len_rev'] is not None:
                conditions.append('mss.option.remote.value:' + str(flows[0]['mss_value_rev']))
                if (flows[0]['mss_value_rev'] < flows[0]['mss_value_fwd']):
                    conditions.append('mss.option.received.deflated')
                elif (flows[0]['mss_value_rev'] == flows[0]['mss_value_fwd']):
                    conditions.append('mss.option.received.unchanged')
                else:
                    conditions.append('mss.option.received.inflated')
            else:
                conditions.append('mss.option.received.absent')

        return conditions
