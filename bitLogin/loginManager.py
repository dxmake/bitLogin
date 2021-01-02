import time
import socket
import re
import json
import urllib.request
import urllib.parse

from .encryption.srun_md5 import get_md5
from .encryption.srun_sha1 import get_sha1
from .encryption.srun_base64 import get_base64
from .encryption.srun_xencode import get_xencode

class loginManager:
	def __init__(self,
		urlHost = 'http://10.0.0.55',
		urlUserInfo = '/cgi-bin/rad_user_info',
		urlChallenge = '/cgi-bin/get_challenge',
		urlSrun = '/cgi-bin/srun_portal',
		n = '200',
		vType = '1',
		acID = '8',
		enc = 'srun_bx1',
		callbackPrefix = 'jQuery1124019502944455313276_'
	):
		self.urlUserInfo = urlHost + urlUserInfo
		self.urlChallenge = urlHost + urlChallenge
		self.urlSrun = urlHost + urlSrun

		self.n = n
		self.vType = vType
		self.acID = acID
		self.enc = enc

		self.callbackPrefix = callbackPrefix

		self.__getUserInfo()

	def login(self, username, password):
		self.username = username
		self.password = password

		self.__getUserInfo()
		if ('error' in self.userInfo) and (self.userInfo['error']=='ok'):
			print('Device already logged on.')
			return
		self.__getChallenge()
		self.__srunLogin()

	def logout(self):
		self.__getUserInfo()
		if ('error' in self.userInfo) and (self.userInfo['error']!='ok'):
			print('Device not online.')
			return
		self.__srunLogout()

	def __getUserInfo(self):
		print('--> Getting user info...')
		reqData = {}
		self.userInfo = self.__requestAndParse(self.urlUserInfo, reqData)

	def __getChallenge(self):
		print('--> Getting challenge...')
		reqData = {
			'username': self.username,
			'ip': self.userInfo['client_ip']
		}
		self.challenge = self.__requestAndParse(self.urlChallenge, reqData)

	def __srunLogin(self):
		print('--> Encrypting login info...')
		infoEncrypted, tokenMd5L, chkStrEncrypted = self.__generateLoginInfo()

		print('--> Srun Logging in...')
		reqData = {
			'action': 'login',
			'username': self.username,
			'password': tokenMd5L,
			'ac_id': self.acID,
			'ip': self.userInfo['client_ip'],
			'info': infoEncrypted,
			'chksum': chkStrEncrypted,
			'n': self.n,
			'type': self.vType
		}
		self.srunResponse = self.__requestAndParse(self.urlSrun, reqData)
		print('--> '+self.srunResponse['ploy_msg'])

	def __generateLoginInfo(self):
		params = {
			'username': self.username,
			'password': self.password,
			'ip': self.userInfo['client_ip'],
			'acid': self.acID,
			'enc_ver': self.enc
		}
		token = self.challenge['challenge']

		info = re.sub("'",'"',str(params))
		info = re.sub(' ','',info)
		infoEncrypted = '{SRBX1}' + get_base64(get_xencode(info, token))

		tokenMd5 = get_md5('', token)
		tokenMd5L = '{MD5}' + tokenMd5

		chkStr = ''
		chkStr += token + self.username
		chkStr += token + tokenMd5
		chkStr += token + self.acID
		chkStr += token + self.userInfo['client_ip']
		chkStr += token + self.n
		chkStr += token + self.vType
		chkStr += token + infoEncrypted
		chkStrEncrypted = get_sha1(chkStr)

		return infoEncrypted, tokenMd5L, chkStrEncrypted

	def __srunLogout(self):
		print('--> Srun Logging out...')
		reqData = {
			'action': 'logout',
			'ac_id': self.acID,
			'ip': self.userInfo['online_ip'],
			'username': self.userInfo['user_name']
		}
		self.srunResponse = self.__requestAndParse(self.urlSrun, reqData)



	def __requestAndParse(self, url, reqData):
		reqData['callback'] = self.callbackPrefix + str(int(time.time()*1000))
		req = urllib.request.Request(
			url=url + '?' + urllib.parse.urlencode(reqData),
			method = 'GET'
		)

		resp = urllib.request.urlopen(req)
		respStr = resp.read().decode('utf-8')
		resp.close()

		prefixLen = len(reqData['callback']) + 1
		postfixLen = 1
		
		respJson = json.loads(respStr[prefixLen:-postfixLen])
		# print(respJson)
		return respJson

	def _test(self):
		print('---> Test')

		self.username = '0000000000'
		self.password = '00000000'

		self.__getUserInfo()
		print(self.userInfo)
		
		self.__getChallenge()
		print(self.challenge)

		self.__srunLogin()
		print(self.srunResponse)

		# self.logout()
		# print(self.srunResponse)


if __name__ == '__main__':
	bit = loginManager()
	bit._test()
