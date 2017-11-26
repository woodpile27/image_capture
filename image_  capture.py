from scapy.all import *
import scapy_http.http as HTTP
import threading
import time
from collections import OrderedDict
import os
import glob
import redis


REDIS = redis.Redis(host='localhost', port=6379)


def save_to_redis(pkt):
    data = str(pkt)
    try:
        REDIS.rpush("image", data)
    except Exception, e:
        print e
        print 'save to redis failed'


def get_from_redis():
    while True:
        try:
            data = REDIS.lpop("image")
            if data:
                pkt = Ether(data)
                #pkt = RadioTap(data)
                parse_picture(pkt)
            else:
                print 'image is empty'
                time.sleep(1)
        except:
            print 'get from redis error'


def parse_picture(pkt):
#    if HTTP.HTTPRequest in pkt and 'image' in pkt.Accept:
#        print pkt.Host + pkt.Path
    if HTTP.HTTPResponse in pkt and Raw in pkt:
        content_type = pkt.sprintf("%HTTPResponse.Content-Type%")
        content_enco = pkt.sprintf("%HTTPResponse.Content-Encoding%")
        if 'image' in content_type:
            image_type = content_type.split('/')[-1][0:-1]
            identity = "%s:%d" % (pkt[IP].dst,pkt[TCP].dport)
            global count
            count += 1
            idens[identity] = count
        else:
            return None
        load = str(pkt[Raw].load)
        file_name = "./image/image_%d.%s" % (count, image_type)
        with open('%s' % file_name, 'wb') as f:
            f.write(load)
            print '%s write to file successful' % file_name
    elif Raw in pkt:
        identity = "%s:%d" % (pkt[IP].dst,pkt[TCP].dport)
        if identity in idens.keys():
            iden_count = idens[identity]
            file_name = glob.glob('./image/*_%d.*' % iden_count)[0]
            load = str(pkt[Raw].load)
            with open(file_name, 'ab') as f:
                f.write(load)
                print '%s additional write to file successful' % file_name
    else:
        pass


def sniff_image():
    sniff(iface='ens33', prn=save_to_redis, filter='tcp and port 80')


def iden_update():
    while True:
        try:
            idens.popitem(last=False)
            time.sleep(1)
        except KeyError:
            time.sleep(2)


if __name__ == '__main__':
    count = 0
    idens = OrderedDict()
    threading.Thread(target=sniff_image).start()
    threading.Thread(target=iden_update).start()
    threading.Thread(target=get_from_redis).start()
