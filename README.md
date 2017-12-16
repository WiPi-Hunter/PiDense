
```
        ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
       ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░▌      ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
       ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ 
       ▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌▐░▌    ▐░▌▐░▌          ▐░▌          
       ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ 
       ▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
       ▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌   ▐░▌ ▐░▌ ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ 
       ▐░▌               ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌    ▐░▌▐░▌          ▐░▌▐░▌          
       ▐░▌           ▄▄▄▄█░█▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌     ▐░▐░▌ ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ 
       ▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░▌      ▐░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
        ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 

                             Monitor illegal wireless network activities.
              ------------------------------------------------------------------------------

```

<p align="center">
<img src="https://img.shields.io/badge/Python-2-yellow.svg"></a> <img src="https://img.shields.io/badge/license-GPLv3-red.svg">
<a href="http://www.blackhat.com/eu-17/arsenal/schedule/#wipi-hunter---wifi-pineapple-activities-detection-9091"><img src="https://rawgit.com/toolswatch/badges/master/arsenal/2017.svg"></a>
</p>

#### Purpose

Monitor  **illegal wireless network activities.**

+ Similar SSID broadcasts
+ Same SSID broadcasts
+ Calculates unencrypted wireless networks density
+ Watches SSID broadcasts at the blacklist.

#### Capabilities

+ Calculates Unencrypted wireless network density
+ Finds same ssid, different encryption

#### Working Principle for PiDense

+ Collects all the packets from Wireless Networks.
+ Analyzes all the beacon packets. 
+ If PiDens detects more than defined threshold of OPN number, or different encryption with same SSID info ;
+ Logs the activity with some extra information within defined template.

#### Soon to be added features 

+ Blacklist SSID analysis
+ Company name setting for illegal wireless attack activities (Monitoring)

#### Example
+ Video: https://www.youtube.com/watch?v=hsMz6zM-yks
