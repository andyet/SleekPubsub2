from sleekxmpp.xmlstream.matcher.stanzapath import StanzaPath
from sleekxmpp.xmlstream.handler.callback import Callback
from sleekxmpp.plugins import stanza_pubsub as Pubsub

CONFIG_MAP = {}

class SleekPubsub2(object):
    def __init__(self, xmpp, thoonk):
        self.xmpp = xmpp
        self.thoonk = thoonk
		
		self.xmpp.registerHandler(Callback('pubsub create', StanzaPath("iq@type=set/pubsub/create"), self.handleCreateNode)) 
		self.xmpp.registerHandler(Callback('pubsub configure', StanzaPath("iq@type=set/pubsub_owner/configure"), self.handleConfigureNode))
		self.xmpp.registerHandler(Callback('pubsub delete', StanzaPath('iq@type=set/pubsub_owner/delete'), self.handleDeleteNode))
		self.xmpp.registerHandler(Callback('pubsub publish', StanzaPath("iq@type=set/pubsub/publish"), self.handlePublish)) 
		self.xmpp.registerHandler(Callback('pubsub getitems', StanzaPath('iq@type=get/pubsub/items'), self.handleGetItems))
		self.xmpp.registerHandler(Callback('pubsub delete item', StanzaPath('iq@type=set/pubsub/retract'), self.handleRetractItem))
        self.xmpp.registerHandler(Callback('pubsub get configure', StanzaPath('iq@type=get/pubsub_owner/configure'), self.handleGetNodeConfig))
		self.xmpp.registerHandler(Callback('pubsub defaultconfig', StanzaPath('iq@type=get/pubsub_owner/default'), self.handleGetDefaultConfig)) 
		self.xmpp.registerHandler(Callback('pubsub subscribe', StanzaPath('iq@type=set/pubsub/subscribe'), self.handleSubscribe)) 
		self.xmpp.registerHandler(Callback('pubsub unsubscribe', StanzaPath('iq@type=set/pubsub/unsubscribe'), self.handleUnsubscribe)) 

        #TODO: registerHandler for handleSetAffilation, handleGetAffilation, handleGetSubscriptions
		
        self.xmpp.add_event_handler("session_start", self.start)
		self.xmpp.add_event_handler("changed_subscription", self.handlePresenceSubscribe)
		self.xmpp.add_event_handler("got_online", self.handleGotOnline)
		self.xmpp.add_event_handler("got_offline", self.handleGotOffline)

        def handleCreateNode(self, iq):
            pass

        def handleConfigureNode(self, iq):
            pass

        def handleDeleteNode(self, iq):
            pass

        def handlePublish(self, iq):
            pass

        def handleGetItems(self, iq):
            pass

        def handleRetractItem(self, iq):
            pass

        def handleGetNodeConfig(self, iq):
            pass

        def handleGetDefaultConfig(self, iq):
            pass

        def handleSubscribe(self, iq):
            pass

        def handleUnsubscribe(self, iq):
            pass

        def handleSetAffiliation(self, iq):
            pass

        def handleGetAffiliation(self, iq):
            pass

        def handleGetSubscriptions(self, iq):
            pass
