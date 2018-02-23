from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpRequestResponse
from burp import IHttpService
from burp import IProxyListener
from burp import IScannerListener
from burp import IHttpListener
from burp import IScanQueueItem
from burp import IInterceptedProxyMessage
from java.io import PrintWriter
from burp import ITab
import json
from base64 import b64encode
import os
import requests
from datetime import datetime
from java.net import URL
from java.io import File
from urlparse import urlparse
from javax.swing import ImageIcon,JFrame, JLabel, JButton, JTextField, JComboBox, JPanel
from java.awt.Image import SCALE_SMOOTH
from java.awt import Font, Color


class BurpExtender(IBurpExtender,IScannerListener,ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self.helpers = callbacks.helpers
        callbacks.setExtensionName("Orchestron-Plugin")
        self.frame=JPanel()
        self.frame.setSize(1024, 786)
        self.frame.setLayout(None)
        self.scanner_results=[]
        self.plugin_path=os.getcwd()
        callbacks.registerScannerListener(self)
        lbl0=JLabel("Orchestron Webhook:")
        lbl0.setFont(Font("", Font.BOLD, 12))
        lbl0.setForeground(Color(0xFF7F50));
        lbl0.setBounds(60,20,200,20)
        lbl2=JLabel("Webhook Url: ")
        lbl2.setBounds(60,80,100,20)
        self.txt2=JTextField('',300)
        self.txt2.setBounds(200, 80, 220,24)
        lbl3=JLabel("Authorization Token: ")
        lbl3.setBounds(60,110,200,20)
        self.txt3=JTextField('',60)
        self.txt3.setBounds(200, 110, 220,24)
        lbl4=JLabel("Engagement-ID: ")
        lbl4.setBounds(60,140,200,20)
        self.txt4=JTextField('',40)
        self.txt4.setBounds(200, 140, 220,24)
        button2=JButton('Push Results',actionPerformed=self.push)
        button2.setBounds(200, 170, 120,24)
        self.message = JLabel('')
        self.message.setBounds(330,170,180,24)
        self.frame.add(lbl0)
        self.frame.add(lbl2)
        self.frame.add(self.txt2)
        self.frame.add(lbl3)
        self.frame.add(self.txt3)
        self.frame.add(lbl4)
        self.frame.add(self.txt4)
        self.frame.add(button2)
        self.frame.add(self.message)

        callbacks.customizeUiComponent(self.frame)
        callbacks.addSuiteTab(self)

    def newScanIssue(self, issue):
        self.scanner_results.append(issue)

    def push(self,event):
        file_name = '{0}/BurpResults.xml'.format(self.plugin_path)
        self._callbacks.generateScanReport('XML',self.scanner_results,File(file_name))
        # print(self.plugin_path)
        if self.txt2.text and self.txt3.text:
            webhook_url = self.txt2.text
            auth_token = self.txt3.text
            engagement_id = ''
            if self.txt4.text:
                engagement_id=self.txt4.text
            files = {'file': open(file_name,'rb')}
            headers = {'Authorization': 'Token {0}'.format(auth_token), 'X-Engagement-ID': engagement_id}
            r = requests.post(webhook_url, files=files, headers=headers)
            if r.status_code == 200:
                print('Results pushed Successfully', r.json())
            else:
                print('Unable to push Result. Please Check WebHook URL and Authorization Token.')
        else:
            print('Please provide WebHook URL and Authorization Token')

    def parse_burp(self, file):
        pass

    def getTabCaption(self):
        return 'Orchestron'
    def getUiComponent(self):
        return self.frame
