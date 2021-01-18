# Mitre ATT & CK

The purpose of the app is to show how much your environment covers the techniques and tactics of the miter attack, helping the SOC to direct the forces to areas that are less covered

***For the application to work fully, it is necessary to install "Splunk Common Information Model (CIM)"***

***Add an alert on the dashboard***:

![Alt Text](files/Alert_configure.gif)

***Example of the completed panel***:

![Alt Text](files/Environmental_coverage.jpeg)

***Example of the triggered alerts panel***:

![Alt Text](files/Triggered_alerts.jpeg)

***Alerts priority panel***:

![Alt Text](files/Alerts_Priority.PNG)


If you don't want to use the demo alerts I used in the example, just rename the file ***"default/savedsearches.conf"*** to ***"default/savedsearches.conf.old"***.

**Obs:** By default, alerts are summarized in the **"summary"** index, but you can change to the desired index by going to the app's settings.



