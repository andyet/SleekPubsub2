from thoonk.pubsub import Pubsub
from sleekpubsub2.interface import XMPPInterface
from sleekxmpp.componentxmpp import ComponentXMPP
from sleekpubsub2.handlers import SleekPubsub2
import ConfigParser as configparser
import logging

from optparse import OptionParser


if __name__ == '__main__':

    optp = OptionParser()
    optp.add_option('--daemon', action="store_true", dest='daemonize', help="run as daemon")
    optp.add_option('-q','--quiet', help='set logging to ERROR', action='store_const', dest='loglevel', const=logging.ERROR, default=None)
    optp.add_option('-d','--debug', help='set logging to DEBUG', action='store_const', dest='loglevel', const=logging.DEBUG, default=None)
    optp.add_option('-v','--verbose', help='set logging to COMM', action='store_const', dest='loglevel', const=5, default=None)
    optp.add_option("-c","--config", dest="configfile", default="config.ini", help="set config file to use")
    opts,args = optp.parse_args()


    logging.basicConfig(level=opts.loglevel, format='%(levelname)-8s %(message)s')
    logging.info("Not daemonized")


    print "loaded modules"
    p = Pubsub(listen=True, db=10)
    print p.get_feeds()
    print p.feed_exists('test')
    print "pubsub"
    i = XMPPInterface()
    print "interface"
    xmpp = ComponentXMPP('pubsub.recon', 'secreteating', '127.0.0.1', 5230)
    print "xmpp"
    sleekpubsub = SleekPubsub2(xmpp, p)
    i.add_sleekpubsub(sleekpubsub)
    print "Sleekpubsub"
    p.register_interface(i)
    print "registered"
    print xmpp.connect()
    print "connected"
    xmpp.process()
    print "processed"
