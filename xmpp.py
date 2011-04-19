from thoonk.pubsub import Pubsub
from sleekpubsub2.interface import XMPPInterface
from sleekxmpp.componentxmpp import ComponentXMPP
from sleekpubsub2.handlers import SleekPubsub2

p = Pubsub(listen=True, db=0)
i = XMPPInterface()
xmpp = ComponentXMPP('pubsub.recon', 'secreteating', '127.0.0.1', 5230)
sleekpubsub = SleekPubsub2(xmpp, p)
p.register_interface(i)
xmpp.connect()
xmpp.process()
