#!/bin/bash

#++++++++++++++++++++
# Init Globals      +
#++++++++++++++++++++
function init_globals(){
        CIPHERS=""
        SSL_VERSION_STR="-ssl3 -tls1 -tls1_1 -tls1_2"
}

#++++++++++++++++++++++
# Init Scan Vars      +
#++++++++++++++++++++++
function init_scan_vars(){
        NUM_SUCCESS=0
    NUM_FAIL=0
    COUNTER=1
}

#++++++++++++++++++++++++++
# Init Falgs              +
#++++++++++++++++++++++++++
function init_flags(){
        SERVER_ADDRESS="localhost"
        SERVER_PORT="443"
        GET="false"
        CIPHER_SUITE="ALL:@STRENGTH"
        TLS_VERSION="all"
        UNSUPPORTED="true"
        QUIET="false"
}

#+++++++++++++++++++++++++++++++++++++++
# Function to print a line in the help +
#+++++++++++++++++++++++++++++++++++++++
function print_help_line(){
        echo "$1" | awk '{ printf "   %-10s ", $1 ; for (i=2; i<=NF; i++) printf $i" "; printf "\n\n"}'
}

#+++++++++++++++++++++++++++++++++++++++++
# Function to print a header in the help +
#+++++++++++++++++++++++++++++++++++++++++
function print_help_header(){
        tput bold
        echo "$1";echo
        tput sgr0
}

#+++++++++++++++++++++++++++++
# Function to print the help +
#+++++++++++++++++++++++++++++
function print_help(){
        echo
        print_help_header "Usage: $0 [any other flags...]"
        print_help_line  "-h:   Help"
        print_help_line  "-o:   Set the openssl binary. Default is openssl"
        print_help_line  "-s:   Destination server and port seperated by colon. Default is localhost:443"
        print_help_line  "-g:   For each cipher try to send GET request and print response status"
        print_help_line  "-c:   Specify which SSL/TLS cipher suites to use. Default is 'ALL:@STRENGTH'"
        print_help_line  "-v:   Specify which SSL/TLS verions to use. Options are: all, sslv3, tlsv1, tlsv11, tlsv12. Default is all"
        print_help_line  "-f:   Don't print unsupported ciphers"
        print_help_line  "-q:   Be Quiet"
        echo
        echo
        print_help_header  "Written by DrorM"
        print_help_header  "      Radware QA"
        echo
}

#+++++++++++++++++++++++++
# Check usage is correct +
#+++++++++++++++++++++++++
function parse_cli_command(){
        # Init all flags
        init_flags

        # Call getopt program to use all the flags and break them
        TEMP=$(getopt -o s:c:v:o:fhqg -n "$0" -- "$@")

        # Caes getopt failed
        if [ $? != 0 ] ; then
                echo "Terminating..." >&2; exit 1
        fi

        # Note the quotes around `$TEMP': they are essential!
        eval set -- "$TEMP"

        # Use all the flags and init flags and variables accordingly
        while true; do
                case "$1" in
                -h ) print_help; exit 0;;
                -o ) OPENSSL_BIN=$2; shift 2;;
                -s ) SERVER_ADDRESS=`echo $2 | awk -F":" '{print $1}'`;
                         SERVER_PORT=`echo $2 | awk -F":" '{print $2}'`; shift 2;;
                -g ) curl_version; GET="true"; shift;;
                -c ) CIPHER_SUITE=$2; shift 2;;
                -v ) TLS_VERSION=$2; shift 2;;
                -f ) UNSUPPORTED="false"; shift;;
                -q ) QUIET="true"; shift;;
                * ) break ;;
                esac
        done

        if [ "$OPENSSL_BIN" == "" ]; then
                OPENSSL_BIN="openssl"
        fi

        if [ "$SERVER_PORT"     == "" ]; then
                SERVER_PORT="443"
        fi
}

#+++++++++++++++++++++++++
# Verify CURL Version    +
#+++++++++++++++++++++++++
function curl_version(){
        SSL_VER=$(curl -V | sed -e 's/ /\r\n/g' | grep -i "openssl" | cut -d'/' -f2 | cut -d'.' -f1)
        if [ "$SSL_VER" != "1" ]; then
                echo "To use this script with traffic your CURL must me compiled with openssl 1.0.0 and up!"
                echo "Terminating..." >&2; exit 1
        fi
}

#+++++++++++++++++++++++++
# Init Ciphers Array     +
#+++++++++++++++++++++++++
function init_ciphers_array(){
        # Get the list of ciphers
        ciphers_cmd="$OPENSSL_BIN ciphers '$CIPHER_SUITE'"
        CIPHERS=$(eval "$ciphers_cmd" | sed -e 's/:/ /g')

        # Validate the cipher suite entered
        if [ ${#CIPHERS[@]} -eq 1 ] && [ "${CIPHERS[0]}" == "" ]; then
                echo "Bad Cipher suite..."
                exit 1
        fi
}

#+++++++++++++++++++++++++
# Init ssl Array         +
#+++++++++++++++++++++++++
function init_ssl_array(){
        # When the user chooses to run only handshake, we use openssl
        # so he array should be initialized with the openssl ssl/tls
        # version format
        if [ "$GET" == "false" ];then
                case "$TLS_VERSION" in
                        # all is the default so no need to change
                        all )   ;;
                        sslv3 ) SSL_VERSION_STR="-ssl3";;
                        tlsv1 ) SSL_VERSION_STR="-tls1";;
                        tlsv11 ) SSL_VERSION_STR="-tls1_1";;
                        tlsv12 ) SSL_VERSION_STR="-tls1_2";;
                        *) echo "Wrong SSL/TLS Version..."; exit 1;;
                esac
        # When the user chooses to run traffic using each cipher, we will
        # use CURL so the array should be initialized with the CURL
        # ssl/tls version format
        else
                case "$TLS_VERSION" in
                        all )   SSL_VERSION_STR="--sslv3 --tlsv1 --tlsv1.1 --tlsv1.2";;
                        sslv3 ) SSL_VERSION_STR="--sslv3";;
                        tlsv1 ) SSL_VERSION_STR="--tlsv1";;
                        tlsv11 ) SSL_VERSION_STR="--tlsv1.1";;
                        tlsv12 ) SSL_VERSION_STR="--tlsv1.2";;
                        *) echo "Wrong SSL/TLS Version..."; exit 1;;
                esac
        fi
}

#++++++++++++++++++++++
# Print Scan Results  +
#++++++++++++++++++++++
function print_scan_results(){
        echo; print_help_header "List of ciphers supported ($NUM_SUCCESS):"
    for i in `seq 0 $NUM_SUCCESS`; do
        if [ -n ${SUCCESSFUL[$i]} ] && [ "${SUCCESSFUL[$i]}" != "" ]; then
            echo -e "\t$((i + 1)).\t${SUCCESSFUL[$i]}"
        fi
    done

        # User choosed to print also the failed ciphers
        if [ "$UNSUPPORTED" == "true" ]; then
                echo; print_help_header "List of ciphers that are NOT supported by the server:"
                for i in `seq 0 $NUM_FAIL`; do
                        failedCipher=$(echo "${FAILED[$i]}" | awk -F" " '{print $1}')
                        if [ -n "$failedCipher" ] && [ "${FAILED[$i]}" != "" ]; then
                                echo -e "\t$((i + 1)).\t${FAILED[$i]}"
                        fi
                done
        fi

        echo
}

#++++++++++++++++
# Test Ciphers  +
#++++++++++++++++
function test_ciphers(){
        init_scan_vars

        # Init result arrays
        declare -a SUCCESSFUL=()
    declare -a FAILED=()

        # Get the numbers of ciphers to scan
        NUM_CIPHERS=`echo ${CIPHERS[@]} | sed 's/ /\n/g' | wc -l`
        for CIPHER in ${CIPHERS[@]}; do
                if [ "$QUIET" == "false" ]; then
                        echo -n "(""$COUNTER""/""$NUM_CIPHERS"") Testing $CIPHER..."
                fi

                # Run the choosen test method
                if [ "$GET" == "false" ]; then
            res=$(echo -e "GET / HTTP/1.1\r\nConnection: Close\r\n\r\n" | $OPENSSL_BIN s_client -cipher "$CIPHER" "$SSL_VERSION" -connect "$SERVER_ADDRESS":"$SERVER_PORT" -servername "$SERVER_ADDRESS" 2>&1)
                else
                        res=$(curl https://"$SERVER_ADDRESS":"$SERVER_PORT" --ciphers "$CIPHER" "$SSL_VERSION" -k -v 2> sess.log)
                fi

                # In case that the handshake/fetch has failed
                if [ "$?" != "0" ] ; then
                        if [ "$QUIET" == "false" ]; then
                                echo "Fail"
                        fi

                        # Get the error
                        if [ "$GET" == "false" ]; then
                                error=$(echo -n $res | cut -d':' -f6)
                        else
                                error=$(cat sess.log | grep error | head -n 1 | cut -d':' -f5)
                        fi

                        # Store the error in the failed array
            FAILED[NUM_FAIL]=`echo "$CIPHER - ($error)"`

                        if [ "$COUNTER" != "$NUM_CIPHERS" ]; then
                                let NUM_FAIL+=1
                        fi
                # In case that the handshake/fetch has passed
        else
            if [ "$QUIET" == "false" ]; then
                                if [ "$GET" == "true" ]; then
                                        echo -n "Pass "
                                        tput bold
                                        # Print the return code of the HTML fetch
                                        cat sess.log | grep "< HTTP" | awk -F" " '{print $3" "$4}'
                                        tput sgr0
                                else
                                        echo "Pass"
                                fi
                        fi

                        # Store the cipher in the successful array
            SUCCESSFUL[NUM_SUCCESS]=`echo "$CIPHER"`
                        if [ "$COUNTER" != "$NUM_CIPHERS" ]; then
                                let NUM_SUCCESS+=1
                        fi
        fi
        let COUNTER+=1
        done
        print_scan_results
}

#+++++++++++++++++
# Test Versions  +
#+++++++++++++++++
function test_versions(){
        # Declare on the ssl/tls versions to be tested array
        declare -a SSL_VER_ARRAY=($SSL_VERSION_STR)
        for SSL_VERSION in "${SSL_VER_ARRAY[@]}"; do
                tput bold
                echo Using $SSL_VERSION | sed 's/-//g'
                tput sgr0
                echo
                test_ciphers
        done
}

#++++++++++++++++++++++++++++++++++++
#                MAIN               +
#++++++++++++++++++++++++++++++++++++
init_globals
parse_cli_command $@
init_ssl_array
init_ciphers_array
echo
print_help_header "Obtaining cipher list from $($OPENSSL_BIN version)."
test_versions

