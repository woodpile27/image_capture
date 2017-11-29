from scapy.all import *
import scapy_http.http as HTTP
import threading
import time
import os
import redis
from operator import itemgetter


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
        except:
            print 'get from redis error'
        if data:
            pkt = Ether(data)
            #pkt = RadioTap(data)
            parse_picture(pkt)
        else:
            print 'image is empty'
            time.sleep(1)


def parse_picture(pkt):
#    if HTTP.HTTPRequest in pkt and 'image' in pkt.Accept:
#        print pkt.Host + pkt.Path
    if HTTP.HTTPResponse in pkt and Raw in pkt:
        content_type = pkt.sprintf("%HTTPResponse.Content-Type%")
        try:
            content_leng = int(pkt.sprintf("%HTTPResponse.Content-Length%")[2:-1])
        except:
            content_leng = int(pkt.sprintf("%HTTPResponse.Status-Line%").split()[-1][:-1])
        content_enco = pkt.sprintf("%HTTPResponse.Content-Encoding%")
        if 'image' in content_type:
            image_type = content_type.split('/')[-1][0:-1]
            identity = "%s:%d" % (pkt[IP].dst,pkt[TCP].dport)
            seq = pkt.seq
            ack = pkt.ack
            global count
            count += 1
        else:
            return None
        load = str(pkt[Raw].load)
        data = {
                'seq': seq, 
                'data': load
                }
        idens[identity] = {
                        'image_type': image_type, 
                        'content-length': content_leng, 
                        'now-length': len(load), 
                        'count': count, 
                        'ack': ack, 
                        'datas': [data]
                        }
        if len(load) == content_leng:
            save_to_file(identity)
    elif Raw in pkt and TCP in pkt:
        identity = "%s:%d" % (pkt[IP].dst,pkt[TCP].dport)
        seq = pkt.seq
        ack = pkt.ack
        if identity in idens.keys() and ack == idens[identity]['ack']:
            load = str(pkt[Raw].load)
            data = {
                    'seq': seq, 
                    'data': load
                    }
            idens[identity]['datas'].append(data)
            idens[identity]['now-length'] += len(load)
            if idens[identity]['now-length'] == idens[identity]['content-length']:
                save_to_file(identity)
    else:
        pass


def save_to_file(identity):
    data = ''
    image_type = idens[identity]['image_type']
    count = idens[identity]['count']
    rows = idens[identity]['datas']
    rows_by_seq = sorted(rows, key=itemgetter('seq'))
    for i in rows_by_seq:
        data += i['data']
    file_name = "./image/image_%d.%s" % (count, image_type)
    with open('%s' % file_name, 'wb') as f:
        f.write(data)
        print '%s write to file successful' % file_name
    del idens[identity]


def sniff_image():
    sniff(iface='ens33', prn=save_to_redis, filter='tcp and port 80')


if __name__ == '__main__':
    count = 0
    idens = {}
    threading.Thread(target=sniff_image).start()
    threading.Thread(target=get_from_redis).start()
