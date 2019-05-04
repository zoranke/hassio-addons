#!/usr/bin/env python
# coding=utf-8
"""
 Copyright (C) 2010-2018, lidicn


"""


import asyncio
from homeassistant.helpers.entity import Entity
from homeassistant.components.sensor import PLATFORM_SCHEMA
from homeassistant.const import CONF_NAME
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity import async_generate_entity_id
import logging

import time
import hmac
from os import popen
from re import search
from json import loads
from re import compile
from sys import stdout
from hashlib import sha1
from requests import get
from requests import post
from random import randint
from urllib.request import urlopen
from urllib.request import Request
from urllib.parse import urlencode
from json import JSONDecoder
from urllib.error import HTTPError
from datetime import datetime
from urllib.parse import quote
from base64 import encodestring
import requests
_Log=logging.getLogger(__name__)

DEFAULT_NAME = 'aliddns'
friendly_name = '阿里云DDNS'

CONF_ACCESS_ID = 'access_id'
CONF_ACCESS_KEY = 'access_key'
CONF_DOMAIN = 'domain'
CONF_SUB_DOMAIN = 'sub_domain'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_ACCESS_ID): cv.string,
    vol.Required(CONF_ACCESS_KEY): cv.string,
    vol.Required(CONF_DOMAIN): cv.string,
    vol.Required(CONF_SUB_DOMAIN): cv.string,
    vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
})

@asyncio.coroutine
def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    """Setup the sensor platform."""
    sensor_name = config.get(CONF_NAME)
    access_id = config.get(CONF_ACCESS_ID)
    access_key = config.get(CONF_ACCESS_KEY)
    domain = config.get(CONF_DOMAIN)
    sub_domain = config.get(CONF_SUB_DOMAIN)
    if access_id == None or access_key == None or domain == None or sub_domain == None:
        _Log.error('Aliyun Ddns: Pls enter access_id,access_key,domain,subdomain!')

    async_add_devices([AliYunDdnsSensor(hass,sensor_name,friendly_name,access_id,access_key,domain,sub_domain)],True)

class AliYunDdnsSensor(Entity):
    """Representation of a Sensor."""

    def __init__(self,hass,sensor_name,friendly_name,access_id,access_key,domain,sub_domain):
        """Initialize the sensor."""
        self._state = None
        self._hass = hass
        self.entity_id = async_generate_entity_id(
            'sensor.{}', sensor_name, hass=self._hass)

        self.attributes = {}
        self.friendly_name = friendly_name
        self.Aliyun_API_URL = "https://alidns.aliyuncs.com/?"
        self.access_id = access_id
        self.access_key = access_key
        self.domain = domain
        self.sub_domain = sub_domain
        self.Aliyun_API_Type = "A"

    def AliyunSignature(self,parameters):
        sortedParameters = sorted(parameters.items(), key=lambda parameters: parameters[0])
        canonicalizedQueryString = ''
        for (k, v) in sortedParameters:
            canonicalizedQueryString += '&' + self.CharacterEncode(k) + '=' + self.CharacterEncode(v)
        stringToSign = 'GET&%2F&' + self.CharacterEncode(canonicalizedQueryString[1:])
        h = hmac.new((self.access_key + "&").encode('ASCII'), stringToSign.encode('ASCII'), sha1)
        signature = encodestring(h.digest()).strip()
        return signature
    def CharacterEncode(self,encodeStr):
        encodeStr = str(encodeStr)
        res = quote(encodeStr.encode('utf-8'), '')
        res = res.replace('+', '%20')
        res = res.replace('*', '%2A')
        res = res.replace('%7E', '~')
        return res


    def AliyunAPIPOST(self,Aliyun_API_Action):
        Aliyun_API_SD = {
            'Format': 'json',										# 使用 JSON 返回数据，也可使用 XML
            'Version': '2015-01-09',								# 指定所使用的 API 版本号
            'AccessKeyId': self.access_id,
            'SignatureMethod': 'HMAC-SHA1',							# 目前仅支持该算法
            'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),	# ISO8601 标准的 UTC 时间
            'SignatureVersion': '1.0',								# 签名算法版本为 1.0
            'SignatureNonce': randint(0, 99999999999999),			# 生成随机唯一数
            'Action': Aliyun_API_Action
        }
        return Aliyun_API_SD

    def check_record_id(self,sub_domain,domain):
        Aliyun_API_Post = self.AliyunAPIPOST('DescribeDomainRecords')
        Aliyun_API_Post['DomainName'] = domain
        Aliyun_API_Post['Signature'] = self.AliyunSignature(Aliyun_API_Post)
        Aliyun_API_Post = urlencode(Aliyun_API_Post)
        Aliyun_API_Request = get(self.Aliyun_API_URL + Aliyun_API_Post)
        # print('Status code: ',  str(Aliyun_API_Request.status_code))
        self.domainRecords = '';
        try:
            self.domainRecords = Aliyun_API_Request.text
        except HTTPError as e:
            print(e.code)
            print(e.read())
        result = JSONDecoder().decode(self.domainRecords)		# 接受返回数据
        result = result['DomainRecords']['Record']	# 缩小数据范围
        times = 0			# 用于检查对应子域名的记录信息
        check = 0			# 用于确认对应子域名的记录信息
        for record_info in result:					# 遍历返回数据
            if record_info['RR'] == sub_domain:	# 检查是否匹配
                check = 1; break;					# 确认完成结束
            else:
                times += 1							# 进入下个匹配
        if check:
            result = int(result[times]['RecordId'])	# 返回记录数值
        else:
            result = -1								# 返回失败数值
        return result


    def my_ip_json(self):
        try:
            ret = requests.get("http://members.3322.org/dyndns/getip")
        except requests.RequestException as ex:
            #cls.err("network problem:{0}".format(ex))
            return None

        if ret.status_code != requests.codes.ok:
            #cls.err("Failed to get current public IP: {0}\n{1}" \
                    #.format(ret.status_code, ret.content))
            return None

        return ret.content.decode('utf-8').rstrip("\n")

    def my_ip_popen(self):
        get_ip_method = popen('curl -s pv.sohu.com/cityjson?ie=utf-8')				# 获取外网 IP 地址
        get_ip_responses = get_ip_method.readlines()[0]								# 读取 HTTP 请求值
        get_ip_pattern = compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')	# 正则匹配 IP
        get_ip_value = get_ip_pattern.findall(get_ip_responses)[0]					# 寻找匹配值
        return get_ip_value															# 返回 IP 地址

    def my_ip_chinanetwork(self):
        opener = urlopen('http://www.net.cn/static/customercare/yourip.asp')
        strg = opener.read().decode('gbk')
        ipaddr = search('\d+\.\d+\.\d+\.\d+',strg).group(0)
        return ipaddr

    def my_ip(self):

        ip1 = self.my_ip_json()
        ip2 = self.my_ip_popen()
        ip3 = self.my_ip_chinanetwork()
        # if ip1 == ip2 == ip3 == ip4:
            # print("[Success] Verified IP Address...")
            # return ip + random.randint(0,3)					# 开个玩笑
        # else:
            # print("[FAILED] No-Verified IP Address...")
            # return ip1
        return ip1

    def old_ip(self,Aliyun_API_RecordID):
        Aliyun_API_Post = self.AliyunAPIPOST('DescribeDomainRecordInfo')
        Aliyun_API_Post['RecordId'] = Aliyun_API_RecordID
        Aliyun_API_Post['Signature'] = self.AliyunSignature(Aliyun_API_Post)
        Aliyun_API_Post = urlencode(Aliyun_API_Post)
        Aliyun_API_Request = get(self.Aliyun_API_URL + Aliyun_API_Post)
        result = JSONDecoder().decode(Aliyun_API_Request.text)
        return result['Value']

    def add_dns(self,domainIP):
        Aliyun_API_Post = self.AliyunAPIPOST('AddDomainRecord')
        Aliyun_API_Post['DomainName'] = self.domain
        Aliyun_API_Post['RR'] = self.sub_domain
        Aliyun_API_Post['Type'] = self.Aliyun_API_Type
        Aliyun_API_Post['Value'] = domainIP
        Aliyun_API_Post['Signature'] = self.AliyunSignature(Aliyun_API_Post)
        Aliyun_API_Post = urlencode(Aliyun_API_Post)
        Aliyun_API_Request = get(self.Aliyun_API_URL + Aliyun_API_Post)

    def delete_dns(self,Aliyun_API_RecordID):
        Aliyun_API_Post = self.AliyunAPIPOST('DeleteDomainRecord')
        Aliyun_API_Post['RecordId'] = Aliyun_API_RecordID
        Aliyun_API_Post['Signature'] = self.AliyunSignature(Aliyun_API_Post)
        Aliyun_API_Post = urlencode(Aliyun_API_Post)
        Aliyun_API_Request = get(self.Aliyun_API_URL + Aliyun_API_Post)

    def update_dns(self,Aliyun_API_RecordID, Aliyun_API_Value):
        Aliyun_API_Post = self.AliyunAPIPOST('UpdateDomainRecord')
        Aliyun_API_Post['RecordId'] = Aliyun_API_RecordID
        Aliyun_API_Post['RR'] = self.sub_domain
        Aliyun_API_Post['Type'] = self.Aliyun_API_Type
        Aliyun_API_Post['Value'] = Aliyun_API_Value
        Aliyun_API_Post['Signature'] = self.AliyunSignature(Aliyun_API_Post)
        Aliyun_API_Post = urlencode(Aliyun_API_Post)
        Aliyun_API_Request = get(self.Aliyun_API_URL + Aliyun_API_Post)

    def set_dns(self,Aliyun_API_RecordID, Aliyun_API_Enabled):
        Aliyun_API_Post = self.AliyunAPIPOST('SetDomainRecordStatus')
        Aliyun_API_Post['RecordId'] = Aliyun_API_RecordID
        Aliyun_API_Post['Status'] = "Enable" if Aliyun_API_Enabled else "Disable"
        Aliyun_API_Post['Signature'] = self.AliyunSignature(Aliyun_API_Post)
        Aliyun_API_Post = urlencode(Aliyun_API_Post)
        Aliyun_API_Request = get(self.Aliyun_API_URL + Aliyun_API_Post)

    def send_mail(self,content):
        return post(
            "https://api.mailgun.net/v3/example.org/messages",
            auth=("api", "key-"),
            data={"from": "Your Name <me@mail.example.org>",
                "to": ["i@example.org", "admin@example.org"],
                "subject": "[Python Report] IP update from ISP",
                "text": content})

    def get_time(self):
        return "[" + time.strftime('#%y%m%d-%H:%M', time.localtime(time.time())) + "]"



    @property
    def name(self):
        """Return the name of the sensor."""
        return self.friendly_name

    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        return self.attributes

    @property
    def icon(self):
        """Return the icon to use in the frontend, if any."""
        return 'mdi:message-bulleted'

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._state

    @asyncio.coroutine
    def async_update(self):
        """Fetch new state data for the sensor.

        This is the only method that should fetch new data for Home Assistant.

        """

        rc_value = self.my_ip()
        rc_record_id = self.check_record_id(self.sub_domain, self.domain);		# 获取记录信息

        tips = self.get_time()
        if rc_record_id < 0:							# 若接受失败数值
            self.add_dns(rc_value)							# 添加 DNS　解析记录
            tips += " DNS Record was added, value [" + rc_value + "]."
        else:
            rc_value_old = self.old_ip(rc_record_id)
            if rc_value == rc_value_old:				# 检查 IP 是否匹配
                tips += " Same DNS Record..."			# 跳过 DNS 更新
            else:
                # delete_dns(rc_record_id)				# 删除 DNS 解析
                # add_dns(rc_record_id)					# 新增 DNS 解析
                self.update_dns(rc_record_id, rc_value)		# 更新 DNS 解析
                tips += " DNS Record was updated from [" + rc_value_old + "] to [" + rc_value + "]."
                #send_mail(tips)

        self._state = tips
        self.attributes['当前公网ip'] = rc_value
        self.attributes['之前公网ip'] = rc_value_old
        self.attributes['更新时间'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
