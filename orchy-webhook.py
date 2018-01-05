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
        callbacks.setExtensionName("Orchy-Webhook")
        self.frame=JPanel()
        self.frame.setSize(1024, 786)
        self.frame.setLayout(None)
        self.plugin_path=os.getcwd()
        self.db_file_path = os.path.join(os.getcwd(),'burp_db.json')
        self.cwe_dict = json.load(open(self.db_file_path,'r'))
        self.results={}
        self.severity_dict = {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Information': 0,
            'Info': 0,
            }
        self.urls = []
        self.confidence_dict = {
            'Certain': 3,
            'Firm': 2,
            'Tentative': 1
            }


        callbacks.registerScannerListener(self)

        button1 = JButton(ImageIcon(((ImageIcon(self.plugin_path+"/refresh.jpg")).getImage()).getScaledInstance(13, 13, SCALE_SMOOTH)),actionPerformed=self.refresh)
        button1.setBounds(30,50,22,22)
        lbl0=JLabel("Orchestron Webhook:")
        lbl0.setFont(Font("", Font.BOLD, 12))
        lbl0.setForeground(Color(0xFF7F50));
        lbl0.setBounds(60,20,200,20)
        lbl1=JLabel('Host')
        lbl1.setBounds(60,50,100,20)
        self.txt1=JComboBox()
        self.txt1.setBounds(200, 50, 220,24)
        lbl2=JLabel("Webhook Url")
        lbl2.setBounds(60,80,100,20)
        self.txt2=JTextField('',300)
        self.txt2.setBounds(200, 80, 220,24)
        lbl3=JLabel("Authorization Token")
        lbl3.setBounds(60,110,200,20)
        self.txt3=JTextField('',60)
        self.txt3.setBounds(200, 110, 220,24)
        lbl4=JLabel("Engagement-ID")
        lbl4.setBounds(60,140,200,20)
        self.txt4=JTextField('',40)
        self.txt4.setBounds(200, 140, 220,24)
        button2=JButton('Push Results',actionPerformed=self.push)
        button2.setBounds(200, 170, 120,24)
        self.message = JLabel('')
        self.message.setBounds(330,170,180,24)
        self.frame.add(button1)
        self.frame.add(lbl0)
        self.frame.add(lbl1)
        self.frame.add(self.txt1)
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

    def refresh(self,event):
        self.txt1.removeAllItems()
        for host in self.results.keys():
            self.txt1.addItem(host)
        self.message.text = ''

    def newScanIssue(self, issue):
        callbacks = self._callbacks
        # print "New Issue Identified:"+issue.getUrl().toString()
        if callbacks.isInScope(issue.getUrl()) == 1:
            self.tmp= issue.getUrl()
            self.scheme = self.tmp.protocol
            self.port = self.tmp.port
            self.fqdn =self.tmp.host
            if self.port == -1:
                if self.scheme == 'https':
                    self.port = 443
                elif self.scheme == 'http':
                    self.port = 80
                else:
                    self.scheme = 'http'
                    self.port = 80
            self.host=str(self.scheme+'://'+self.fqdn+':'+str(self.port))

            if not self.results:
                self.results[self.host]={'scan_dict':{}}


            for host in self.results.keys():
                if host == self.host:
                    if str(issue.getIssueType()) in self.cwe_dict.keys():
                        name = self.cwe_dict.get(str(issue.getIssueType()), '')[1]
                        cwe_id = self.cwe_dict.get(str(issue.getIssueType()), '')[0]
                    else:
                        name = 'Burp IssueType - {0}'.format(str(issue.getIssueType()))
                        cwe_id = 0


                    if name in self.results[host]['scan_dict'].keys():
                        old_evidance = self.results[host]['scan_dict'][name].get('evidences')
                        for httpmessage in issue.getHttpMessages():
                            request = (httpmessage.getRequest().tostring() if httpmessage.getRequest() else None)
                            request = b64encode(request.encode('utf-8'))
                            response = (httpmessage.getResponse().tostring() if httpmessage.getResponse() else None)
                            response = b64encode(response.encode('utf-8'))
                            info_dict = {
                                        'url': issue.getUrl().toString(),
                                        'name': issue.getIssueName(),
                                        'request': request,
                                        'response': response
                                        }
                            old_evidance.append(info_dict)
                    else:
                        severity = self.severity_dict.get(issue.getSeverity(), '')
                        confidence = self.confidence_dict.get(issue.getConfidence(), '')
                        evidences = []
                        for httpmessage in issue.getHttpMessages():
                            request = (httpmessage.getRequest().tostring() if httpmessage.getRequest() else None)
                            request = b64encode(request.encode('utf-8'))
                            response = (httpmessage.getResponse().tostring() if httpmessage.getResponse() else None)
                            response = b64encode(response.encode('utf-8'))
                            info_dict = {
                                        'url': issue.getUrl().toString(),
                                        'name': issue.getIssueName(),
                                        'request': request,
                                        'response': response
                                        }
                            evidences.append(info_dict)
                        self.results[host]['scan_dict'][name] = {
                                'description': issue.getIssueDetail(),
                                'remediation': '',
                                'severity': severity,
                                'cwe':cwe_id,
                                'evidences':evidences
                            }




                else:
                    self.results[self.host]={'scan_dict':{}}
                    if str(issue.getIssueType()) in self.cwe_dict.keys():
                        name = self.cwe_dict.get(str(issue.getIssueType()), '')[1]
                        cwe_id = self.cwe_dict.get(str(issue.getIssueType()), '')[0]
                    else:
                        name = 'Burp IssueType - {0}'.format(str(issue.getIssueType()))
                        cwe_id = 0

                    severity = self.severity_dict.get(issue.getSeverity(), '')
                    confidence = self.confidence_dict.get(issue.getConfidence(), '')
                    evidences = []
                    for httpmessage in issue.getHttpMessages():
                        request = (httpmessage.getRequest().tostring() if httpmessage.getRequest() else None)
                        request = b64encode(request.encode('utf-8'))
                        response = (httpmessage.getResponse().tostring() if httpmessage.getResponse() else None)
                        response = b64encode(response.encode('utf-8'))
                        info_dict = {
                                    'url': issue.getUrl().toString(),
                                    'name': issue.getIssueName(),
                                    'request': request,
                                    'response': response
                                    }
                        evidences.append(info_dict)
                    self.results[host]['scan_dict'][name] = {
                            'description': issue.getIssueDetail(),
                            'remediation': '',
                            'severity': severity,
                            'cwe':cwe_id,
                            'evidences':evidences
                        }


    def push(self,event):
        if self.txt1.getSelectedItem():
            vulns={}
            vulns['tool']='Burp'
            vulns['vulnerabilities']=[]
            for k,v in self.results[self.txt1.getSelectedItem()]['scan_dict'].items():
                vulnerability = {
                        'name': str(k),
                        'description': v.get('description',''),
                        'remediation': '',
                        'severity': v.get('severity',None),
                        'cwe': v.get('cwe',0),
                        'evidences': v.get('evidences',None)
                    }
                vulns['vulnerabilities'].append(vulnerability)

            if self.txt2.text and self.txt3.text:
                webhook_url=self.txt2.text
                auth_token=self.txt3.text
                engagement_id=''
                if self.txt4.text:
                    engagement_id=self.txt4.text
                req_headers={'Authorization':'Token '+auth_token,'X-Engagement-ID':engagement_id}
                req = requests.post(webhook_url,headers=req_headers,json={'vuls':vulns})
                if req.status_code == 200:
                    self.message.text= "Result pushed successfully"
                    with open('./orchy_log.txt','a') as orchy_log:
                        orchy_log.write(req.content +'\n')
                        orchy_log.close()
                else:
                    with open('./orchy_log.txt','a') as orchy_log:
                        orchy_log.write(req.content+'\n')
                        orchy_log.close()
                    self.message.text= "Failed"

    def getTabCaption(self):
        return 'Orchy-Webhook'
    def getUiComponent(self):
        return self.frame



