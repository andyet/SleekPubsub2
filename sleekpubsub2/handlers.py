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
        self.redis = thoonk.redis
		
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

        def handleGotOffline(self, presence):
            subs = self.redis.smembers('xmpp.sub_expires.{%s}' % presence['from'].full)
            subs += self.redis.smembers('xmpp.sub_expires.{%s}' % presence['from'].bare)
            if subs:
                for sub in subs:
                    node, subid = sub.split('\x00')
                    self.unsubscribe(node, subid)

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

        def is_affiliation(self, node, jid, affiliations):
            pass

        def is_pending(self, node, jid):
            pass

        def add_pending(self, node, jid):
            pass
        
        def rem_pending(self, node, jid):
            pass

        def send_auth_request(self, node, subscriber):
            #where jid is the subscribing jid
            pass

        def node_exists(self, node):
            pass

        def get_subid(self, node, jid):
            pass

        def subscribe(self, node, jid, config, node_config):
            if config.get('pubsub#expire', '') == 'presence' or node_config.get('pubsub#expire', '') == 'presence':
                self.redis.sadd('xmpp.sub_expires.{%s}' % jid, "%s\x00%s" % (node, subid))
            self.redis.hset('xmpp.subs.jid.{%s}' % node, subid, jid)
            if config:
                self.redis.hset('xmpp.subs.config.{%s}' % node, subid, json.sdump(config))
            self.redis.sadd('xmpp.jid.subs.{jid}', '%s\x00%s' % (subid, node))

        def unsubscribe(self, node, subid=None, sjid=None, fjid='__internal__'):
            jid = self.redis.hget('xmpp.subs.jid.{%s}' % node, subid)
            if not jid:
                pass #raise
            if fjid == '__internal__':
                pass
            elif self.is_admin(fjid) or self.is_affiliation(node, fjid, 'owner'):
                pass
            elif fjid.full != jid and fjid.bare != jid:
                pass #raise
            self.redis.hdel('xmpp.subs.jid.{%s}' % node, subid)
            self.redis.hdel('xmpp.subs.config.{%s}' % node, subid)
            self.redis.sdel('xmp.jid.subs.{%s}' % jid, '%s\x00%s' % (node, subid))
            self.redis.sdel('xmpp.sub_expires.{%s}' % jid, "%s\x00%s" % (node, subid))

        def can_unsubscribe():
            pass

        def can_subscribe(self, iq, fjid, node, sjid, config):
            if self.is_admin(fjid) or self.is_affiliation(node, fjid, 'owner'):
                self.rem_pending(node, sjid) #no longer pending, cause the admin/owner says
                return 'subscribed'
            elif self.is_pending(node, sjid):
                raise XMPPError(condition='not-authorized', etype='auth', extension='pending-subscription', extension_ns='http://jabber.org/protocol/pubsub#errors')
                #TODO: send another auth request?
            elif (fjid != sjid and fjid != sjid.bare):
                raise XMPPError(condition='bad-request', etype='modify', extension='invalid-jid', extension_ns='http://jabber.org/protocol/pubsub#errors')
            elif is_affiliation(node, sjid, 'outcast'):
                raise XMPPError(condition='forbidden', etype='auth')
            else:
                am = node_config.get('pubsub#access_model', 'open')
                if am == 'open':
                    return 'subscribed'
                elif am == 'presence':
                    #is in the roster and authorized?
                    if self.xmpp.roster[iq['to'].bare].has_jid(fjid.bare) and self.xmpp.roster[iq['to'].bare][fjid.bare]['to']:
                        return 'subscribed'
                    else:
                        raise XMPPError(condition='not-authorized', etype='auth', extension='presence-subscription-required', extension_ns='http://jabber.org/protocol/pubsub#errors')
                elif am == 'roster':
                    #is in the roster and authorized and in one of the roster groups allowed?
                    if self.xmpp.roster[iq['to'].bare].has_jid(fjid.bare) and self.xmpp.roster[iq['to'].bare][fjid.bare]['to'] and set(self.xmpp.roster[iq['to'].bare][fjid.bare]['groups']).intersect(set(self.thoonk[node].config['pubsub#roster_groups_allowed'])):
                        return 'subscribed'
                    else:
                        raise XMPPError(condition='not-authorized', etype='auth', extension='not-in-roster-group', extension_ns='http://jabber.org/protocol/pubsub#errors')
                elif am == 'whitelist':
                    if set((sjid.full, sjid.bare)).intersect(set(self.thoonk[node].config['pubsub#whitelist'])):
                        return 'subscribed'
                    else:
                        raise XMPPError(condition='not-allowed', etype='cancel', extension='closed-node', extension_ns='http://jabber.org/protocol/pubsub#errors')
                elif am == 'authorize':
                    self.add_pending(node, sjid)
                    self.send_auth_request(node, sjid)
                    iq.reply()
                    iq.clear()
                    sub = iq['pubsub']['subscripton']
                    sub['node'] = node
                    sub['jid'] = sjid
                    sub['subscription'] = 'pending'
                    iq.reply()
                    return 'pending'
                return 'subscribed'

        def handleSubscribe(self, iq):
            node = iq['pubsub']['subscribe']['node']
            jid = stanza['pubsub']['subscribe']['jid']
            config = stanza['pubsub']['subscribe']['options']
            if not jid: jid = iq['from'].bare

            if not self.node_exists(node):
                logging.warning("Unable to subscribe %(subscriber)s to %(node)s due to %(condition)s" % {'condition': 'item-not-found','node': node, 'subscriber': jid})
                raise XMPPError(condition='item-not-found', etype='cancel')
            else:
                node_config = self.get_config(node)
                try:
                    result = self.can_subscribe(iq, iq['from'], node, jid, config, node_config)
                except XMPPError as e:
                    logging.warning("Unable to subscribe %(subscriber)s to %(node)s due to %(condition)s + %(extension)s" % {'condition': e.condition, 'extension': e.extension, 'node': node, 'subscriber': jid})
                    raise

                if result == 'subscribed':
                    subid = self.subscribe(node, sjid, config, node_config)
                    iq.reply()
                    iq.clear()
                    sub = iq['pubsub']['subscripton']
                    sub['subid'] = subid
                    sub['node'] = node
                    sub['jid'] = jid
                    sub['subscription'] = result
                    iq.send()

        def handleUnsubscribe(self, iq):
            pass

        def handleSetAffiliation(self, iq):
            pass

        def handleGetAffiliation(self, iq):
            pass

        def handleGetSubscriptions(self, iq):
            pass
