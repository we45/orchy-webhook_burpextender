## Burp Extender for Orchestron Webhook

#### How to install and run Orchestron Webhook Burp Extender?
  1. Download the Orchy-webhook burp extender file <br>
  2. Download Jython 2.7.0 - Installer.jar from http://www.jython.org/downloads.html 

**Run the following command:**


```
    sudo java -jar jython-installer-2.7.0.jar -s -t standard -d /usr/local/jython-2.7.0 && sudo ln -s /usr/local/jython-2.7.0/jython /usr/local/bin/
    sudo /usr/local/jython-2.7.0/bin/pip install requests==2.9.2
```

  3. Give Jython environment (.jar) file location as ``/usr/local/jython-2.7.0/jython.jar`` in Burp Extender options tab.
  4. Load the orchy-webhook.py from extension tab.
  5. Add the url to scope in burp, then run active scan.<br>
    **Note:** Url should be add to scope before running active scan.
  6. Click refresh button on orchy-webhook  burp extension.
  7. Select the host once the active scan is done.
  8. Create webhook for the Testing applciation in orchestron conmsole and copy the webhook url to clipboard.
  9. Give Web Hook Url, Authenication Token, Engagement-ID(if neccessary) in orchy-webhook  burp extension
  10. Clck push result
  11. After results is pushed, orchy response will be stored in orchy-log.txt file for future reference.
