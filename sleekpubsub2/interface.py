from thoonk.pubsub import ACL, Interface

class XMPPInterface(Interface):
    name = "XMPPPubsub"

    def add_sleekpubsub(self, sleekpubsub):
        self.sleekpubsub = sleekpubsub

    def publish_notice(self, feed, item, id):
        print "publish: %s[%s]: %s" % (feed, id, item)
        self.sleekpubsub.thoonk_publish(feed, item, id)

    def retract_notice(self, feed, id):
        print "retract: %s[%s]" % (feed, id)
        self.sleekpubsub.thoonk_retract(feed, id)

    def create_notice(self, feed):
        print "created: %s" % feed
        self.sleekpubsub.thoonk_create(feed)

    def delete_notice(self, feed):
        print "deleted: %s" % feed
        self.sleekpubsub.thoonk_delete(feed)

    def finish_notice(self, feed, id, item, result):
        print "finished: %s[%s]: %s -> %s" % (feed, id, item, result)
        self.sleekpubsub.thoonk_finish(feed, id, item, result)


