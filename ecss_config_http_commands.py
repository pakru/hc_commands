import xml.etree.ElementTree as ET
import requests
import time
import base64


class httpTerm:
	httpReqTimeout = 10  # make timeout in seconds
	loginSuccess = False
	lastCode = 200
	def __init__(self,host='127.0.0.1',port='9999',login='admin',passwd='password', protocol = 'http'):
		self.host = host
		self.port = port
		self.protocol = protocol
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xs="http://www.w3.org/2001/XMLSchema-instance"><login password=\""""+ passwd +"""\" user=\""""+ login +"""\"/></in>"""
		self.httpHeader = {'Content-Type': 'text/xml'}
		try:
			self.response = requests.post(protocol+'://'+ self.host +':'+ self.port +'/system/login', data = self.xmlRequest, headers = self.httpHeader, timeout = self.httpReqTimeout)
		except requests.exceptions.ConnectionError:
			print('Cannot connect to '+self.host+':'+self.port+' Connection refused.')
		except requests.exceptions.Timeout:
		 	print('Cannot connect to '+self.host+':'+self.port+' Request timeout.')
		except Exception as e:
			print('Cannot connect to '+self.host+':'+self.port+' due to exception: '+format(e))
		else:	# do if no exception ocure
			self.httpCookie = self.response.headers.get('Set-Cookie') ## remember auth cookie
			if self.response.status_code != 200 :
				print('Http termianl login error with code: '+ str(self.response.status_code))
				self.loginSuccess = False
			else:
				self.loginSuccess = True
				print('Http termianl login success!')
	
	def makeHttpPOST(self, xmlString, commandURL, reqTimeout = httpReqTimeout):
		self.httpHeader = {'Cookie' : self.httpCookie, 'Content-Type' : 'text/xml'}
		try:
			self.response = requests.post(self.protocol+'://' + self.host + ':'+ self.port + commandURL, data = xmlString, headers = self.httpHeader, timeout = reqTimeout)
		except requests.exceptions.ConnectionError:
			print('Connection refused during http request execution...')
			self.lastCode = 404
		except requests.exceptions.Timeout:
		 	print('Cannot connect to '+self.host+':'+self.port+' Request timeout.')
		 	self.lastCode = 408
		except Exception as e:
			print('Cannot connect to '+self.host+':'+self.port+' due to exception: '+format(e))
			self.lastCode = 404
		else:
			self.lastCode = self.response.status_code
		if not (self.lastCode in range(200,210)):				# если код результата не ок, то пишем, всё содержимое, что нам пришло.
			print(self.response.content.decode('utf-8'))
			print('Code:' + str(self.lastCode))
		return self.lastCode

		
	def domainDeclare(self, domainName):
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="hc_domain_declare.xsd">
    <domain name=\""""+ domainName +"""\" grant_user="true" grant_admin="true"/>
</in>"""
		self.commandURL = '/commands/domain_declare'
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		return self.lastCode

	def domainRemove(self, domainName):
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="hc_domain_remove.xsd">
    <domain force="true" name=\""""+ domainName +"""\" />
</in>"""
		self.commandURL = '/commands/domain_remove'
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		return self.lastCode
	
	def sipSubscriberCreate(self, domainName, address, group, passwd='auto-generation', context='default_routing', login='login-as-number', authQop='no'):
		self.iface = address + '@' + domainName
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xs="http://www.w3.org/2001/XMLSchema-instance">
    <request domain=\""""+domainName+"""\" iface=\""""+self.iface+"""\" group=\""""+group+"""\" auth_qop=\""""+authQop+"""\" context=\""""+context+"""\" address=\""""+address+"""\" login=\""""+login+"""\" password=\""""+passwd+"""\" />
</in>"""
		self.commandURL = '/commands/sip_user_declare'
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		print()
		if self.lastCode == 206:  													## отработка прогресса деларирования сип-абонента
			self.xmlResponse = ET.fromstring(self.response.content.decode('utf-8'))
			for self.xmlElements in self.xmlResponse.iter('ref'):
				self.refValue=self.xmlElements.get('value')
				#print(self.refValue)
			self.commandURL = '/system/progress'
			self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <progress ref=\""""+ self.refValue +"""\" />
</in>"""
			self.makeHttpPOST(self.xmlRequest,self.commandURL)
			if 'error' in self.response.content.decode('utf-8'):
				self.lastCode = 404
				print(self.response.content.decode('utf-8'))

		return self.lastCode


	def sipSubscriberRemove(self, domainName, address, group):
		self.iface = address + '@' + domainName
		self.commandURL = '/commands/sip_user_remove'
		self.xmlRequest = """<?xml version="1.0"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="sip_user_remove.xsd">
    <request>
        <aliases>
            <alias domain=\"""" + domainName + """\" group=\"""" + group + """\" iface=\""""+ self.iface +"""\" force="true"/>
        </aliases>
    </request>
</in>"""
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		return self.lastCode

	def ssInstall(self, ssFileName, dsNode='ds1'):
		self.commandURL = '/commands/ss_install'
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="ss_install.xsd">
    <request file=\"""" + ssFileName + """\" storage=\"""" + dsNode +"""\" />
</in>"""
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		return self.lastCode

	def ssInstallAll(self, dsNode='ds1'):
		self.commandURL = '/commands/ss_avaliable_show'					## получаем список всех xml ДВОшек
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="ss_avaliable_show.xsd">
    <request storage=\"""" + dsNode +"""\" />
</in>"""		
		self.makeHttpPOST(self.xmlRequest, self.commandURL)

		self.xmlResponse = ET.fromstring(self.response.content.decode('utf-8')) 
		for self.xmlElements in self.xmlResponse.iter('src_ss'):		## ставим все ДВОшки из полученного списка
			self.ssXmlName=self.xmlElements.get('src')
			print('Installing '+str(self.ssXmlName))
			self.ssInstall(ssFileName=self.ssXmlName,dsNode=dsNode)
		return self.lastCode

	def ssAllowForDomain(self, ssName, domainName, dsNode='ds1'):
		self.commandURL = '/commands/ss_acl_add'
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="acl_add.xsd">
   <request storage=\"""" + dsNode +"""\">
    <domains>
        <domain name=\""""+ domainName +"""\">
            <acl name=\"""" + ssName + """\"/>
        </domain>
    </domains>
   </request>
</in>"""
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		if not ( '<ok/>' in self.response.content.decode('utf-8') ):
			print(self.response.content.decode('utf-8'))
			self.lastCode = 403
		return self.lastCode

	def ssAllowAllForDomain(self, domainName, dsNode='ds1'):
		self.commandURL = '/commands/ss_show'
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="ss_show.xsd">
    <request storage=\""""+dsNode+"""\"/>
</in>"""
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		self.xmlResponse = ET.fromstring(self.response.content.decode('utf-8'))
		for self.xmlElements in self.xmlResponse.iter('ss'):		## ставим все ДВОшки из полученного списка
			self.ssFamilyName=self.xmlElements.get('family')
			print('Adding to acl '+str(self.ssFamilyName))
			self.ssAllowForDomain(ssName=self.ssFamilyName,domainName=domainName,dsNode=dsNode)
			#self.ssInstall(ssFileName=self.ssXmlName)
		return self.lastCode

	def ssActivate(self, ssName, address, domainName):
		self.commandURL = '/commands/ss_activate'
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="ss_activate.xsd">
    <request domain=\""""+domainName+"""\">
        <activate ss=\""""+ssName+"""\" address=\""""+address+"""\" />
    </request>
</in>"""
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		return self.lastCode

	def routeCtxAdd(self, domainName, ctxString):
		self.commandURL = '/commands/change_context'
		self.ctxStringXML = bytes(ctxString, encoding = 'utf-8')
		self.ctxStringBase64 = base64.b64encode(self.ctxStringXML).decode('utf-8')
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in>
    <request domain=\""""+domainName+"""\">
        <context>"""+self.ctxStringBase64+"""</context>
    </request>
</in>"""
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		return self.lastCode

	def tcTemplateCreate(self, domainName, templateName, addressFirst, addressesCount):
		self.commandURL = '/commands/tc_meeting'
		self.addressesXML = ''
		'''
		if addressesCount > 120:
			addressesCount = 120
		'''

		#self.grId = 1
		self.grCount = (addressesCount // 100) + 1
		print('grCount :' + str(self.grCount))
		self.groupsXml = ''

		for self.grId in range(1,self.grCount+1):
			self.initAddr = int(addressFirst) + ((self.grId - 1) * 100)
			print('initAddr :'+ str(self.initAddr))
			self.addrCnt = addressesCount - ( (self.grId - 1) * 100 )
			if self.addrCnt > 100:
				self.addrCnt = 100
			print('addrCnt :'+ str(self.addrCnt))
			self.finAddr = (int(addressFirst) + ((self.grId - 1) * 100)) + self.addrCnt
			print('finAddr :'+ str(self.finAddr))

			for self.address in range(self.initAddr, self.finAddr):
				self.addressesXML = self.addressesXML + """<member name=\""""+ str(self.address) +"""\">
                    <property name="role" value="passive" />
                	</member>
                	"""
			self.groupsXml = self.groupsXml + """ <group id=\"""" + str(self.grId) + """\" name=\""""+ str(self.grId) +"""\">
"""+ self.addressesXML +"""</group> 
"""
			self.addressesXML = ''

		
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="hc_tc_meeting.xsd">
    <request domain=\""""+ domainName +"""\">
        <meeting name=\""""+ str(templateName) +"""\" description="test" greeting_url="">
            """+ self.groupsXml +"""           
        </meeting>
    </request>
</in>"""

	

		'''
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="hc_tc_meeting.xsd">
    <request domain=\""""+ domainName +"""\">
        <meeting name=\""""+ str(templateName) +"""\" description="test" greeting_url="">
            <group id="1" name="Group One">
"""+ self.addressesXML +"""</group>
        </meeting>
    </request>
</in>"""

		'''
		print(self.xmlRequest)
		self.makeHttpPOST(self.xmlRequest, self.commandURL)

		return self.lastCode

	def tcPushCfg(self, domainName, masterNumber):
		self.commandURL = '/commands/hc_tc_phone_push'
		self.xmlRequest = """<?xml version="1.0" encoding="UTF-8"?>
<in xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="hc_tc_phone_push.xsd">
    <request domain=\""""+ domainName +"""\" master=\""""+ masterNumber +"""\">
    </request>
</in>"""
		self.makeHttpPOST(self.xmlRequest, self.commandURL)
		return self.lastCode




#req = httpTerm(host='192.168.118.38',port='9999',login='admin',passwd='password')
#print('if login success? ' + format(req.loginSuccess))
#print(req.sipSubscriberCreate(domainName='test.domain',address='1243{1-4}',group='test.py.gr',passwd='1234'))
#print(req.domainDeclare('Py_Domain3'))
#print(req.domainRemove('Py_Domain3'))
#print(req.sipSubscriberRemove(domainName='test.domain', address='{2124-2400}', group='test.py.gr'))
#print(req.ssInstall(ssFileName='ss_chold.xml'))
#print(req.ssInstallAll())
#print(req.ssAllowForDomain(ssName='3WAYs',domainName='Py_Domain'))
#print(req.ssAllowAllForDomain('Py_Domain'))

myctx= """<context domain="Py_Domain" digitmap="auto" name="test_py41">
<rule name="new_rule">
	<conditions><cgpn digits="123"/>
	</conditions>
	<actions>
		<cgpn digits="456"/>
	</actions>
	<result><local/></result>
	</rule>
</context>"""
#print(req.routeCtxAdd(domainName='Py_Domain',ctxString=myctx))

#print(req.tcTemplateCreate('Py_Domain','NewPyTemplate2','1200',10))