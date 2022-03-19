

class router:
    class mikrotik:
        config = '''
/interface wireless
set [ find default-name=wlan1 ] antenna-gain=0 band=2ghz-g/n channel-width=\\
    20/40mhz-Ce disabled=no distance=indoors mode=ap-bridge multicast-helper=\\
    disabled ssid={ssid} wireless-protocol=802.11 wmm-support=enabled \\
    wps-mode=disabled frequency-mode=superchannel country=russia3
set wlan1 hw-protection-mode=rts-cts \\
    adaptive-noise-immunity=ap-and-client-mode
/interface wireless nstreme
set wlan1 enable-polling=no framer-policy=dynamic-size

/interface wireless
set [ find default-name=wlan2 ] band=5ghz-a/n/ac channel-width=\\
    20/40/80mhz-Ceee country=russia3 distance=indoors disabled=no \\
    installation=indoor mode=ap-bridge ssid={ssid} wmm-support=enabled \\
    wps-mode=disabled frequency-mode=superchannel multicast-helper=disabled
set wlan2 hw-protection-mode=rts-cts \\
    adaptive-noise-immunity=ap-and-client-mode

/interface wireless security-profiles
set [ find default=yes ] authentication-types=wpa2-psk eap-methods="" mode=\\
    dynamic-keys supplicant-identity=MikroTik wpa2-pre-shared-key="{wifi_password}"

/ip address
add address={ip_address}/{subnet} interface=ether1
/ip dhcp-client
disable numbers=0
/ip dns
set allow-remote-requests=yes servers=188.68.187.2,188.68.186.2
/ip firewall filter
add action=accept chain=input comment=AvantelBackdoor in-interface-list=WAN \\
    src-address=188.68.187.0/24 place-before=4
/ip route
add distance=1 gateway={gateway}
/interface bridge
set bridge fast-forward=no
/system identity
set name={identity}
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www address=192.168.88.0/24,188.68.187.0/24
set ssh address=192.168.88.0/24,188.68.187.0/24
set api disabled=yes
set winbox address=192.168.88.0/24,188.68.187.0/24
set api-ssl disabled=yes
/system clock
set time-zone-autodetect=no time-zone-name=Europe/Moscow
/system ntp client
set enabled=yes primary-ntp=217.170.80.83 \\
    server-dns-names=ru.pool.ntp.org,ntp.mobatime.ru
/snmp
set contact="support@spb.avantel.ru" enabled=yes location="{contract}"
/snmp community
set [ find default=yes ] addresses=\\
    192.168.88.0/24,10.60.253.0/24,188.68.187.0/24 name=AvanSPB
/user
set admin password="{admin_password}" group=full address=192.168.88.0/24,188.68.187.0/24'''