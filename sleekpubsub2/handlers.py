from sleekxmpp.xmlstream.matcher.stanzapath import StanzaPath
from sleekxmpp.xmlstream.handler.callback import Callback
from sleekxmpp.plugins import stanza_pubsub as Pubsub
import uuid, json
from xml.etree import cElementTree as ET

CONFIG_MAP = {}
AFFILIATIONS = set('owner', 'publisher', 'publisher-only', 'member', 'none', 'outcast')

class SleekPubsub2(object):
    def __init__(self, xmpp, thoonk, default_config={}):
        self.xmpp = xmpp
        self.thoonk = thoonk
        self.default_config = default_config
		
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
		
		self.xmpp.add_event_handler("got_offline", self.handleGotOffline)

        def xmppconfig2thoonkconfig(self, node, config):
            "returns thoonk config dict"
            pass

        def thoonkconfig2xmppconfig(self, node, config):
            "returns xmpp config dict"
            pass

        def handleGotOffline(self, node, config):
            pass

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

        def is_admin(self, jid):
            pass

        def is_affiliation(self, jid, affiliations, node):
            pass

        def can_subscribe(self, iq, fjid, node, sjid, config):
            if self.is_admin(fjid) or self.is_affiliation(fjid, 'owner', node):
                return 'subscribed'
            elif (fjid != sjid and fjid != sjid.bare):
                iq.reply()
                iq.clear()
                iq['error']['condition'] = 'bad-request'
                iq['error']['type'] = 'modify'
                iq['error'].xml.append(ET('{http://jabber.org/protocol/pubsub#errors}invalid-jid'))
                iq.send()
            else:
                am = self.thoonk[node].config.get('pubsub#access_model', 'open')
                if am == 'open':
                    return 'subscribed'
                elif am == 'presence':
                    #is in the roster and authorized?
                    if self.xmpp.roster[iq['to'].bare].has_jid(fjid.bare) and self.xmpp.roster[iq['to'].bare][fjid.bare]['to']:
                        return 'subscribed'
                    else:
                        iq.reply()
                        iq.clear()
                        iq['error']['condition'] = 'not-authorized'
                        iq['error']['type'] = 'auth'
                        iq['error'].xml.append(ET('{http://jabber.org/protocol/pubsub#errors}presence-subscription-required'))
                        iq.send()
                elif am == 'roster':
                    #is in the roster and authorized and in one of the roster groups allowed?
                    if self.xmpp.roster[iq['to'].bare].has_jid(fjid.bare) and self.xmpp.roster[iq['to'].bare][fjid.bare]['to'] and set(self.xmpp.roster[iq['to'].bare][fjid.bare]['groups']).intersect(set(self.thoonk[node].config['pubsub#roster_groups_allowed'])):
                        return 'subscribed'
                    else:
                        iq.reply()
                        iq.clear()
                        iq['error']['condition'] = 'not-authorized'
                        iq['error']['type'] = 'auth'
                        iq['error'].xml.append(ET('{http://jabber.org/protocol/pubsub#errors}not-in-roster-group'))
                        iq.send()
                elif am == 'whitelist':
                    if set((sjid.full, sjid.bare)).intersect(set(self.thoonk[node].config['pubsub#whitelist'])):
                        return 'subscribed'
                    else:
                        iq.reply()
                        iq.clear()
                        iq['error']['condition'] = 'not-allowed'
                        iq['error']['type'] = 'cancel'
                        iq['error'].xml.append(ET('{http://jabber.org/protocol/pubsub#errors}closed-node'))
                        iq.send()
                return 'subscribed'

        def handleSubscribe(self, iq):
            node = iq['pubsub']['subscribe']['node']
            jid = stanza['pubsub']['subscribe']['jid']
            config = stanza['pubsub']['subscribe']['options']
            if not jid: jid = iq['from'].bare
            result = self.can_subscribe(iq, iq['from'], node, jid, config) 

            if result in ('subscribed', 'pending', 'unconfigured'):
                subid = uuid.uuid4().hex
                iq.reply()
                iq.clear()
                sub = iq['pubsub']['subscripton']
                sub['subid'] = subid
                sub['node'] = node
                sub['jid'] = jid
                sub['subscription'] = result

        def handleUnsubscribe(self, iq):
            pass

        def handleSetAffiliation(self, iq):
            pass

        def handleGetAffiliation(self, iq):
            pass

        def handleGetSubscriptions(self, iq):
            pass
