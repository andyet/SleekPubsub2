from sleekxmpp.xmlstream.matcher.stanzapath import StanzaPath
from sleekxmpp.xmlstream.handler.callback import Callback
from sleekxmpp.plugins import stanza_pubsub as Pubsub
import uuid, json
from xml.etree import cElementTree as ET
import types
import logging
from sleekxmpp.exceptions import XMPPError
from sleekxmpp.plugins.stanza_pubsub import EventItem, Subscription

CONFIG_MAP = {}
AFFILIATIONS = set(('owner', 'publisher', 'publisher-only', 'member', 'none', 'outcast'))

class SleekPubsub2(object):

    CUSTOM_ACCESS_MODEL = {}

    def __init__(self, xmpp, thoonk, default_config={}, features=[]):
        self.xmpp = xmpp
        self.thoonk = thoonk
        self.default_config = default_config
        self.redis = thoonk.redis

        self.features = self.process_features(features)

        self.thoonk.register_handler('publish_notice', self.thoonk_publish)
        self.thoonk.register_handler('retract_notice', self.thoonk_retract)
        self.thoonk.register_handler('create_notice', self.thoonk_create)
        self.thoonk.register_handler('delete_notice', self.thoonk_delete)
        
        #self.xmpp.registerHandler(Callback('pubsub create', StanzaPath("iq@type=set/pubsub/create"), self.handleCreateNode)) 
        #self.xmpp.registerHandler(Callback('pubsub configure', StanzaPath("iq@type=set/pubsub_owner/configure"), self.handleConfigureNode))
        #self.xmpp.registerHandler(Callback('pubsub delete', StanzaPath('iq@type=set/pubsub_owner/delete'), self.handleDeleteNode))
        self.xmpp.registerHandler(Callback('pubsub publish', StanzaPath("iq@type=set/pubsub/publish"), self.handlePublish)) 
        #self.xmpp.registerHandler(Callback('pubsub getitems', StanzaPath('iq@type=get/pubsub/items'), self.handleGetItems))
        #self.xmpp.registerHandler(Callback('pubsub delete item', StanzaPath('iq@type=set/pubsub/retract'), self.handleRetractItem))
        #self.xmpp.registerHandler(Callback('pubsub get configure', StanzaPath('iq@type=get/pubsub_owner/configure'), self.handleGetNodeConfig))
        #self.xmpp.registerHandler(Callback('pubsub defaultconfig', StanzaPath('iq@type=get/pubsub_owner/default'), self.handleGetDefaultConfig)) 
        self.xmpp.registerHandler(Callback('pubsub subscribe', StanzaPath('iq@type=set/pubsub/subscribe'), self.handleSubscribe)) 
        self.xmpp.registerHandler(Callback('pubsub unsubscribe', StanzaPath('iq@type=set/pubsub/unsubscribe'), self.handleUnsubscribe)) 

        self.xmpp.registerHandler(Callback('pubsub getsubs', StanzaPath('iq@type=get/pubsub/subscriptions'), self.handleGetSubscriptions))

        #TODO: registerHandler for handleSetAffilation, handleGetAffilation, handleGetSubscriptions
        
        self.xmpp.add_event_handler("got_offline", self.handleGotOffline)

        keys = self.redis.keys('xmpp.sub_expires.presence.{*}')
        for key in keys:
            subs = self.redis.smembers(key)
            for sub in subs:
                node, subid = sub.split('\x00')
                logging.info("Cleaning up stale subscription %s %s" % (node, subid))
                self.unsubscribe(node, subid)

    def process_features(features):
        #TODO: fill this out
        #register feature discovery
        #update default config
        return features

    def xmppconfig2thoonkconfig(self, node, config):
        "returns thoonk config dict"
        if node is not None:
            newconfig = copy.deepcopy(self.thoonk[node].config)
        else:
            newconfig = {'type': 'feed'}
        newconfig['max_items'] = config['pubsub#max_items']
        if 'xmpp_config' not in newconfig:
            newconfig['xmpp_config'] = {}
        newconfig['xmpp_config'].update(config)
        return newconfig

    def thoonkconfig2xmppconfig(self, node):
        "returns xmpp config dict"
        config = copy.deepcopy(self.thoonk[node].config)
        newconfig = config.get('xmpp_config', {'pubsub#node_type': 'leaf'})
        newconfig['pubsub#max_items'] = config['max_items']
        return newconfig

    def thoonk_publish(self, feed, item, id):
        subs = self.redis.hgetall('xmpp.subs.jid.{%s}' % feed)
        if subs:
            msg = self.xmpp.Message()
            msg['from'] = self.xmpp.boundjid
            msg['to'] = '%s'
            try:
                payload = ET.fromstring(item)
            except:
                payload = ET.Element('{http://andyet.net/protocol/sleekpubsub2-payload}payload')
                payload.text = item
            msg['pubsub_event']['items']['node'] = feed
            item = EventItem()
            item['payload'] = payload
            item['id'] = id
            msg['pubsub_event']['items'].append(item)
            msg_str = str(msg)
            #TODO get node config
            for subid in subs:
                #TODO get sub config here
                self.xmpp.send_raw(msg_str % subs[subid])

    def thoonk_retract(self, feed, id):
        pass

    def thoonk_create(self, feed):
        pass

    def thoonk_delete(self, feed):
        pass

    def thoonk_finish(self, feed, id, item, result):
        pass

    def handleGotOffline(self, presence):
        subs = self.redis.smembers('xmpp.sub_expires.presence.{%s}' % presence['from'].full)
        subs.union(self.redis.smembers('xmpp.sub_expires.presence.{%s}' % presence['from'].bare))
        if subs:
            for sub in subs:
                node, subid = sub.split('\x00')
                logging.debug("%s went offline so unsubscribe from %s" % (presence['from'].full, node))
                self.unsubscribe(node, subid)

    def handleCreateNode(self, iq):
        pass

    def handleConfigureNode(self, iq):
        pass

    def handleDeleteNode(self, iq):
        pass

    def handlePublish(self, iq):
        fjid = iq['from'].bare
        node = iq['pubsub']['publish']['node']
        instant_node = False
        auto_create = False
        if not node:
            if 'instant-nodes' not in self.features:
                raise XMPPError(etype='modify', condition='not-acceptable', extention='nodeid-required', extention_ns='http://jabber.org/protocol/pubsub#errors')
            node = uuid.uuid4().hex
            instant_node = True
        if instant_node or not self.node_exists(node):
            if 'auto-create' in self.features:
                #create config from default config merged with publish-options
                config = self.xmpp.plugin['xep_0004'].make_form()
                config['values'] = self.default_config
                if 'publish_options' in iq['pubsub'].plugins:
                    config.merge(iq['pubsub']['publish_options'])
                config = self.xmppconfig2thoonkconfig(None, config['values'])
                self.thoonk.create_feed(node, config)
                self.set_affilation(node, fjid, 'owner')
                auto_create = True
            else:
                raise XMPPError(condition='item-not-found', etype='cancel')
        if not self.is_admin(fjid) and not self.is_affiliation(node, fjid, 'owner') and not self.is_affiliation(node, fjid, 'publisher') and not self.is_affiliation(node, fjid, 'publish-only'):
            raise XMPPError(etype='auth', condition='forbidden')
        #TODO: if too big, error payload-to-big 7.1.3.4
        #TODO: if wrong ns or more than one root element in <item /> error invalid-payload 7.1.3.5
        if not auto_create and 'publish_options' in iq['pubsub'].plugins:
            options = iq['pubsub']['publish_options']['values']
            existing_config = self.thoonkconfig2xmppconfig(node)
            for key in options:
                if options[key] != existing_config.get(key):
                    raise XMPPError(condition='conflict', etype='cancel', extension='precondition-not-met', extension_ns='http://jabber.org/protocol/pubsub#errors')
        item_id = iq['pubsub']['publish']['item']['id']
        if not item_id:
            item_id = uuid.uuid4().hex
        self.thoonk.publish(node, iq['pubsub']['publish']['item'], id=item_id)

    def handleGetItems(self, iq):
        pass

    def handleRetractItem(self, iq):
        pass

    def handleGetNodeConfig(self, iq):
        pass

    def handleGetDefaultConfig(self, iq):
        pass

    def get_config(self, node):
        return self.thoonk[node].config

    def is_admin(self, jid):
        return self.redis.sismember('xmpp.admin', jid)

    def is_affiliation(self, node, jid, affiliation):
        return self.redis.sismember('xmpp.affiliation.{%s}.{%s}' % (affiliation, node), jid)
    
    def set_affiliation(self, node, jid, affiliation):
        self.redis.sadd('xmpp.affiliation.{%s}.{%s}' % (affiliation, node), jid)

    def is_pending(self, node, jid):
        return self.redis.hexists('xmpp.pending.{%s}' % node, jid)

    def add_pending(self, node, jid, subid):
        if subid is None:
            subid = uuid.uuid4().hex
        self.redis.hset('xmpp.pending.{%s}' % node, jid, subid)
    
    def rem_pending(self, node, jid):
        self.redis.hdel('xmpp.pending.{%s}' % node, jid)

    def approve_pending(self, node, jid, subid):
        pass

    def send_auth_request(self, node, subscriber):
        #where jid is the subscribing jid
        pass

    def node_exists(self, node):
        return self.thoonk.feed_exists(node)

    def get_subids(self, node, jid):
        return self.redis.smembers('xmpp.jid.subs.{%s}.{%s}' % (jid, node))

    def subscribe(self, node, jid, config, node_config, subid=None):
        if config is None or not config:
            config = {}
        if subid is None:
            subid = uuid.uuid4().hex
        if config.get('pubsub#expire', '') == 'presence' or node_config.get('pubsub#expire', '') == 'presence':
            self.redis.sadd('xmpp.sub_expires.presence.{%s}' % jid, "%s\x00%s" % (node, subid))
        self.redis.hset('xmpp.subs.jid.{%s}' % node, subid, jid)
        if config:
            self.redis.hset('xmpp.subs.config.{%s}' % node, subid, json.dumps(config))
        self.redis.sadd('xmpp.jid.subs.{%s}.{%s}' % (jid, node), subid)
        return subid

    def unsubscribe(self, node, subid):
        jid = self.redis.hget('xmpp.subs.jid.{%s}' % node, subid)
        self.redis.hdel('xmpp.subs.jid.{%s}' % node, subid)
        self.redis.hdel('xmpp.subs.config.{%s}' % node, subid)
        self.redis.srem('xmpp.jid.subs.{%s}.{%s}' % (jid, node), subid)
        self.redis.srem('xmpp.sub_expires.presence.{%s}' % jid, "%s\x00%s" % (node, subid))

    def can_unsubscribe(self, iq, fjid, node, sjid, subid=None):
        if not self.node_exists(node):
            raise XMPPError(condition='item-not-found', etype='cancel')
        if subid is None or subid == '':
            subids = self.get_subids(node, sjid)
            if len(subids) == 0:
                raise XMPPError(condition='unexpected-request', etype='cancel', extension='not-subscribed', extension_ns='http://jabber.org/protocol/pubsub#errors')
            elif len(subids) > 1:
                raise XMPPError(condition='bad-request', etype='modify', extension='subid-required', extension_ns='http://jabber.org/protocol/pubsub#errors')
            else:
                subid = subids.pop()
        else:
            if not self.redis.sismember('xmpp.jid.subs.{%s}.{%s}' % (sjid, node), subid):
                raise XMPPError(condition='unexpected-request', etype='cancel', extension='not-subscribed', extension_ns='http://jabber.org/protocol/pubsub#errors')
        if self.is_admin(fjid) or self.is_affiliation(node, fjid, 'owner'):
            return True
        elif fjid.full != jid and fjid.bare != jid:
            raise XMPPError(condition='forbidden', etype='auth')
        return True

    def can_subscribe(self, iq, fjid, node, sjid, config, node_config):
        if self.is_admin(fjid) or self.is_affiliation(node, fjid, 'owner'):
            self.rem_pending(node, sjid) #no longer pending, cause the admin/owner says
            return True
        elif self.is_pending(node, sjid):
            raise XMPPError(condition='not-authorized', etype='auth', extension='pending-subscription', extension_ns='http://jabber.org/protocol/pubsub#errors')
            #TODO: send another auth request?
        elif (fjid.full != sjid.full and fjid.bare != sjid.full):
            logging.error("%s %s" % (fjid, sjid))
            raise XMPPError(condition='bad-request', etype='modify', extension='invalid-jid', extension_ns='http://jabber.org/protocol/pubsub#errors')
        elif self.is_affiliation(node, sjid, 'outcast'):
            raise XMPPError(condition='forbidden', etype='auth')
        else:
            am = node_config.get('pubsub#access_model', 'open')
            if am == 'open':
                return True
            elif am == 'presence':
                #is in the roster and authorized?
                if self.xmpp.roster[iq['to'].bare].has_jid(fjid.bare) and self.xmpp.roster[iq['to'].bare][fjid.bare]['to']:
                    return True
                else:
                    raise XMPPError(condition='not-authorized', etype='auth', extension='presence-subscription-required', extension_ns='http://jabber.org/protocol/pubsub#errors')
            elif am == 'roster':
                #is in the roster and authorized and in one of the roster groups allowed?
                if self.xmpp.roster[iq['to'].bare].has_jid(fjid.bare) and self.xmpp.roster[iq['to'].bare][fjid.bare]['to'] and set(self.xmpp.roster[iq['to'].bare][fjid.bare]['groups']).intersect(set(self.thoonk[node].config['pubsub#roster_groups_allowed'])):
                    return True
                else:
                    raise XMPPError(condition='not-authorized', etype='auth', extension='not-in-roster-group', extension_ns='http://jabber.org/protocol/pubsub#errors')
            elif am == 'whitelist':
                if set((sjid.full, sjid.bare)).intersect(set(self.thoonk[node].config['pubsub#whitelist'])):
                    return True
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
                return False
            elif am in self.CUSTOM_ACCESS_MODEL:
                return self.CUSTOM_ACCESS_MODEL[am](iq, fjid, node, sjid, config, node_config)
            return True

    def handleSubscribe(self, iq):
        node = iq['pubsub']['subscribe']['node']
        jid = iq['pubsub']['subscribe']['jid']
        config = iq['pubsub']['subscribe']['options']['options'].getValues()
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
            if result:
                subid = self.subscribe(node, jid, config, node_config)
                iq.reply()
                iq.clear()
                iq['pubsub']['subscription']['subid'] = subid
                iq['pubsub']['subscription']['node'] = node
                iq['pubsub']['subscription']['subscription'] = 'subscribed'
                iq['pubsub']['subscription']['jid'] = str(jid)
                iq.send()

    def handleUnsubscribe(self, iq):
        node = iq['pubsub']['unsubscribe']['node']
        sjid = iq['pubsub']['unsubscribe']['jid']
        fjid = iq['from']
        subid = iq['pubsub']['unsubscribe']['subid']
        try:
            result = self.can_unsubscribe(iq, fjid, node, sjid, subid)
        except XMPPError as e:
            logging.warning("Unable to unsubscribe %(subscriber)s from %(node)s due to %(condition)s + %(extension)s" % {'condition': e.condition, 'extension': e.extension, 'node': node, 'subscriber': sjid})
            raise
        if result:
            self.unsubscribe(node, subid)
            iq.reply()
            iq.clear()
            iq.send()

    def handleSetAffiliation(self, iq):
        pass

    def handleGetAffiliation(self, iq):
        pass

    def handleGetSubscriptions(self, iq):
        #TODO pending!!!!!
        keys = self.redis.keys('xmpp.jid.subs.{%s*}.{*}' % iq['from'].bare)
        print 'xmpp.jid.subs.{%s*}.{*}' % iq['from'].bare
        print keys
        iq.reply()
        for key in keys:
            fullsubs = self.redis.smembers(key)
            data = key[15:]
            jid, node = data.split('}.{')
            node = node[:-1]
            for subid in fullsubs:
                sub = Subscription()
                sub['jid'] = jid
                sub['node'] = node
                sub['subid'] = subid
                sub['subscription'] = 'subscribed'
                iq['pubsub']['subscriptions'].append(sub)
        iq.send()
