# IMS SIP Client
SIP Client for ePDG which allows registering to an IMS and receiving SMS without a mobile connection.
This could, for example be useful for integrating into a project where SMS sending / receiving is required, but there is either no mobile network or a mobile modem is too expensive for

## Disclaimer
This software is provided "as is" without any warranty of any kind. Refer to the license for full details. Use this tool only on systems for which you have explicit authorization.

## THIS IS A WORK IN PROGRESS
This is still very hacky, might not work correctly, and maybe not for all operators.
(but works on my machine)

## Instructions / Setup
The tool is currently configured to register to the IMS and print out any messages received.
The following other tools are also required:
- [SWu-IKEv2](https://github.com/tryption/SWu-IKEv2)
- [USIM-https-server](https://github.com/tryption/USIM-https-server)

Those are forks with slight adaptations to make this work.
Special thanks to @fasferraz for publishing the tools.

*SWu-IKEv2* has been adapted to write details about the negotiated connection into the parent directory. *ims-sip-client* will read the file from the parent directory.
This is why I recommend the following folder structure:
```
IMS-Stack
├── ims-sip-client
├── SWu-IKEv2
└── USIM-https-server
```

First, start the *USIM-https-server*, then *SWu-IKEv2*, and then the *ims-sip-client* with `sudo python3 main.py --msisdn 41790000000` where the MSISDN is the MSISDN of the SIM card connected to the device.