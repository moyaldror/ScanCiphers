# ScanCiphers
A bash script to scan for server supported ciphers

Usage: ./ScanCiphers.sh [any other flags...]

   -h:        Help 

   -s:        Destination server and port seperated by colon. Deafult is localhost:443 

   -g:        For each cipher try to send GET request and print response status 

   -c:        Specify which SSL/TLS cipher suites to use. Default is 'ALL:@STRENGTH' 

   -v:        Specify which SSL/TLS verions to use. Options are: all, sslv3, tlsv1, tlsv11, tlsv12. Default is all 

   -f:        Don't print unsupported ciphers 

   -q:        Be Quiet 



Written by DrorM

      Radware QA
