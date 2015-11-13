#!/bin/bash
##################################################
# CernVM Online Contextualization Scripts v1.0
# ------------------------------------------------
# This is a multifunctional script that implements
# the CernVM Online contextualization mechanism
##################################################
VM_CONFIG_FILE="/etc/cernvm/online.conf"
VM_CA_PATH="/etc/cernvm/keys/CAs"
VM_URL_CONTEXT="https://cernvm-online.cern.ch/api/context"
CERNVM_SITE_CONFIG="/etc/cernvm/site.conf"
CERNVM_DEFAULT_CONFIG="/etc/cernvm/default.conf"
CERNVM_ONLINE_D="/etc/cernvm/online.d"
AMICONFIG="/usr/sbin/amiconfig.sh user --force"
AMICONFIG_API_VERSION="2007-12-15"
AMICONFIG_CONTEXT_PATH="/var/lib/amiconfig-online/"
##################################################

. /etc/cernvm/functions

# Prepare some advanced info
VM_VERSION=$(ls -1 /.installed_cernvm-system* | cut -d\- -f 3)
CERT_CHECK="--cacert ${VM_CA_PATH}/all.pem --capath $VM_CA_PATH"

# Platform-specific flags for the various tools (Mac: -E / linux: -r)
F_SED="-r"
F_GREP="-E"
F_B64="-di"
F_MKTEMP="/tmp/tmp.XXXXXXXX"
F_CURL=""

# Be verbose or silent?
SILENT=0

###############################################
# Parse file in $1 and export the variables
# found in the environment, prefixed with $2
function parse_context {
###############################################
    local FILE=$1
    local VAR_PREFIX=$2

    # Split on new lines
    local IFS=$'\n'
    for LINE in $(cat $FILE); do
        # Process only lines in "KEY=<anything>" format
        if [ $(echo "$LINE" | grep ${F_GREP} -c '^[a-zA-Z0-9_-]+=') -ne 0 ]; then
            V_KEY=$(echo "$LINE" | awk -F'=' '{print $1}')
            V_VAL=$(echo "$LINE" | sed ${F_SED} 's/^[a-zA-Z0-9_-]+=//') # We might encounter '=' again later
            eval "export ${VAR_PREFIX}${V_KEY}=\"\$V_VAL\""
        fi
    done
    
}

###############################################
# Decode base64-encoded contets of the variable
# named in $1 and dump it in the file in $2.
function dump_to_file {
###############################################
    local NAME="$1"
    local FILE="$2"
    VAR=$(eval "echo \$${NAME}")
    # Only if the variable is not empty, create file
    [ ! -z "$VAR" ] && echo "$VAR" | base64 ${F_B64} > "$FILE"
}

###############################################
# Decrypt the contents of the specified file 
# in $1 with the key in $2 and perform the
# common error checks.
function decrypt {
###############################################
    local FILE="$1"
    local SECRET="$2"
    local TMP_FILE=$(mktemp ${F_MKTEMP})
    
    # 1) Remove the 'ENCRYPTED:' prefix and decode
    cat $FILE | sed s/ENCRYPTED://| base64 ${F_B64} > "$TMP_FILE"
    if [ $? -ne 0 ]; then
        # Base64 errors
        rm "$TMP_FILE"
        unset SECRET
        [ $SILENT -eq 0 ] && echo "Error while decoding the contextualization information!" 1>&2
        return 1
    fi
    
    # Decrypt contents and replace old file
    openssl enc -aes-256-cfb8 -d -k "$SECRET" -in "$TMP_FILE" -out "${FILE}"
    if [ $? -ne 0 ]; then
        # OpenSSL errors
        rm "$TMP_FILE"
        unset SECRET
        [ $SILENT -eq 0 ] && echo "Error while decrypting contextualization information!" 1>&2
        return 1
    fi
    
    # Remove temporary file
    rm "$TMP_FILE"
}

###############################################
# Download a file and perform the common error
# checks.
function download {
###############################################
    local URL="$1"
    local FILE="$2"
    [ -z "$FILE" ] && FILE="-"

    # Download checking certificates
    curl --connect-timeout 10 --silent ${F_CURL} ${CERT_CHECK} -o ${FILE} "$URL"

    # Check for errors
    ANS=$?
    if [ $ANS -ne 0 ] && [ $SILENT -eq 0 ]; then
        echo -n "Error while downloading information! " 1>&2
        if [ $ANS -eq 2 ]; then
            echo "Failed to initialize cURL!" 1>&2
        elif [ $ANS -eq 6 ]; then
            echo "Failed to resolve host!" 1>&2
        elif [ $ANS -eq 7 ]; then
            echo "Failed to connect to host!" 1>&2
        elif [ $ANS -eq 23 ]; then
            echo "Could not write the output file!" 1>&2
        elif [ $ANS -eq 28 ]; then
            echo "Operation timed out!" 1>&2
        elif [ $ANS -eq 35 ]; then
            echo "SSL Handshake failed!" 1>&2
        elif [ $ANS -eq 51 ]; then
            echo "Remote server's SSL fingerprint was invalid!" 1>&2
        elif [ $ANS -eq 55 ]; then
            echo "Unable to send data!" 1>&2
        elif [ $ANS -eq 56 ]; then
            echo "Unable to receive data!" 1>&2
        elif [ $ANS -eq 60 ]; then
            echo "Server certificate cannot be authenticated!" 1>&2
        elif [ $ANS -eq 66 ]; then
            echo "Failed to initialize SSL engine!" 1>&2
        elif [ $ANS -eq 67 ]; then
            echo "The user credentials were not accepted!" 1>&2
        elif [ $ANS -eq 77 ]; then
            echo "Error reading CA certificate!" 1>&2
        else
            echo "An unknown cURL error #${ANS} occured!" 1>&2
        fi
    fi
    
    return $ANS
}

###############################################
# Guess the password salt from PIN or UUID
# ---------------------------------------------
# The SALT is generated by summing-up the first
# 4 digits found in the string. If not enough
# digits are found the default digits that will
# be summed-up are: 1,2,3,4
function fetch_salt {
###############################################
    # Fetch ONLY digits from the input
    local PIN=$(echo "$1" | sed s/[^0-9]//g)
    local PIN_LENGTH=${#PIN}
    
    # Set default values if we found less than 4 digits
    local DEFAULT="1234"
    [ $PIN_LENGTH -lt 4 ] && PIN="${PIN}${DEFAULT:$PIN_LENGTH}"
    
    # Calculate and run SUM expression
    local EXPR=$(echo "${PIN:0:4}" | sed ${F_SED} 's/(.)(.)(.)(.)/\1+\2+\3+\4/')
    local SALT=$(eval "echo \$(($EXPR))")
    
    # Make sure its padded with zeroes
    printf "%02.f" ${SALT}
}

###############################################
# Perform contextualization using the specified
# key/password combination. If password is '-'
# the user will be prompted.
function context_download {
###############################################
    local REQ_MODE="$1"
    local CONTEXT_ID="$2"
    local CONTEXT_KEY="$3"
    
    # Calculate salted password checksum
    local SALT=$(fetch_salt "${CONTEXT_ID}")
    local CHECKSUM=$(echo -n "${SALT}${CONTEXT_KEY}${SALT}" | sha1sum | awk '{print $1 }' | tr -d '\n')
    
    # Prepare URL
    local URL="${VM_URL_CONTEXT}?uuid=${VM_UUID}&ver=${VM_VERSION}&${REQ_MODE}=${CONTEXT_ID}&checksum=${CHECKSUM}"

    # Try to download that URL (to STDOUT)
    download "$URL"
    
    # Return the error code
    return $?
}

###############################################
# Update a variable in the VM_CONFIG_FILE
function update_config {
###############################################
    local KEY="$1"
    local VALUE="$2"
    local TMP_FILE=$(mktemp ${F_MKTEMP})
    
    # Strip the specified variable (if exists)
    cat "$VM_CONFIG_FILE" | grep -iv "^$KEY=" > "$TMP_FILE"
    
    # Append the specified variable
    echo "$KEY=$VALUE" >> "$TMP_FILE"
    mv "$TMP_FILE" "$VM_CONFIG_FILE"
    
    # And export the updated value (since the VM_CONFIG_FILE is
    # supposed to be included already)
    eval "export $KEY=$VALUE"

    # Update permissions
    chmod 0644 "$VM_CONFIG_FILE"   
}

###############################################
# Check if the specified pin requires password
# ---------------------------------------------
# If the last digit is odd then the pin referes
# to an encrypted context, otherwise it's
# decrypted
function pin_encrypted {
###############################################
    # Echo '1' if the pin refers to an
    # encrypted context
    echo $1 | grep -c '[13579]$'
}

###############################################
# Display the login banner
function login_banner {
###############################################

    # Display usual banner
    echo ""
    echo "Welcome to CernVM Virtual Machine, version ${VM_VERSION}"
    echo "Machine UUID ${VM_UUID}"
    echo "To contextualize your VM log-in to http://cernvm-online.cern.ch/"
    
}

###############################################
# Prompt the user if we wants to reboot
function reboot_prompt {
###############################################
    echo ""
    echo "The machine needs to be rebooted in order to apply the new configuration."
    echo -n "Please close all the open applications and hit enter to reboot . . . "
    read
    reboot
    exit
}

###############################################
# Perform the complete contextualization sequence
# REQ_MODE can be: 'pin' or 'context_id'
function contextualize {
###############################################
    local REQ_MODE="$1"
    local CONTEXT_ID="$2"
    local CONTEXT_KEY="$3"
    local TMP_FILE=$(mktemp ${F_MKTEMP})
    
    ## Step 1) Download context file
    context_download "${REQ_MODE}" "${CONTEXT_ID}" "${CONTEXT_KEY}" > "$TMP_FILE"
    if [ ! $? -eq 0 ]; then
        [ $SILENT -eq 0 ] && echo "Unable to contextualize the VM!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    
    ## Step 2) Validate download
    if [ ! -s "$TMP_FILE" ]; then
        [ $SILENT -eq 0 ] && echo "The server responded with invalid data!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    
    # Check the header
    local RES_MSG=$(head -n1 "$TMP_FILE" | tr -d '\n')
    if [ "$RES_MSG" == "invalid-checksum" ]; then
        [ $SILENT -eq 0 ] && echo "Invalid password specified!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    if [ "$RES_MSG" == "invalid-request" ]; then
        [ $SILENT -eq 0 ] && echo "An invalid request was performed!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    if [ "$RES_MSG" == "not-found" ]; then
        [ $SILENT -eq 0 ] && echo "The specified contextualization information were not found!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    if [ "$RES_MSG" == "not-authorized" ]; then
        [ $SILENT -eq 0 ] && echo "You are not authorized to pair this instance!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    
    ## Step 3) Check if this is encrypted and decrypt it
    if [ $(grep -c '^ENCRYPTED:' "$TMP_FILE") -ne 0 ]; then
        
        # If the file is encrypted and no key is specified, die
        if [ -z "$CONTEXT_KEY" ]; then
            [ $SILENT -eq 0 ] && echo "The contextualization information are encrypted, but no passphrase was specified!" 1>&2
            rm "$TMP_FILE"
            return 2
        fi
        
        # Decrypt (and replace) file
        decrypt "$TMP_FILE" "$CONTEXT_KEY"
        if [ $? -ne 0 ]; then
            [ $SILENT -eq 0 ] && echo "Unable to contextualize the VM!" 1>&2
            rm "$TMP_FILE"
            return 1
        fi

    fi
    
    ## Step 4) Parse downloaded file and export it's variables to environment
    parse_context "$TMP_FILE" "CTX__"
    if [ $? -ne 0 ]; then
        [ $SILENT -eq 0 ] && echo "Unable to contextualize the VM!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    
    # Validate the parameters inside the context file
    if [ -z "$CTX__EC2_USER_DATA" ]; then
        [ $SILENT -eq 0 ] && echo "Invalid data in the contextualization file!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    
    ## Step 5) Create the amiconfig files
    
    # Prepare the name of the folder
    local C_PATH="${AMICONFIG_CONTEXT_PATH}/${AMICONFIG_API_VERSION}"
    
    # Make directory
    if [ ! -d "$C_PATH" ]; then
        mkdir -p "$C_PATH"
        if [ $? -ne 0 ]; then
            [ $SILENT -eq 0 ] && echo "Unable to create the amiconfig directory!" 1>&2
            rm "$TMP_FILE"
            return 1
        fi
    fi
    
    # Dump user data
    dump_to_file "CTX__EC2_USER_DATA" "${C_PATH}/user-data"
    if [ $? -ne 0 ]; then
        [ $SILENT -eq 0 ] && echo "Unable to create the user-data file!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    
    # Check for ROOT_PUBKEY
    if [ ! -z "$CTX__ROOT_PUBKEY" ]; then
        
        # Make public-keys dir
        local M_PATH="${C_PATH}/meta-data/public-keys/0"
        if [ ! -d "$M_PATH" ]; then
            mkdir -p "$M_PATH"
            if [ $? -ne 0 ]; then
                [ $SILENT -eq 0 ] && echo "Unable to create the meta-data directory!" 1>&2
                rm "$TMP_FILE"
                return 1
            fi
        fi
        
        # Dump root-pubkey
        dump_to_file "CTX__ROOT_PUBKEY" "${M_PATH}/openssh-key"
        if [ $? -ne 0 ]; then
            [ $SILENT -eq 0 ] && echo "Unable to create the file for ROOT SSH key!" 1>&2
            rm "$TMP_FILE"
            return 1
        fi
        
    fi
    
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # EXPERIMENTAL - Because I wanted to update the iAgent credentials...
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # Here you can do various interesting stuff... in your environment 
    # you have all the custom variables defined in CernVM Online prefixed
    # with 'CTX__'.
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if [ ! -z "$CERNVM_ONLINE_D" ] && [ -d "$CERNVM_ONLINE_D" ]; then
        # Scan handlers for custom fields
        PREFIXES=$(ls ${CERNVM_ONLINE_D})
        for K in $PREFIXES; do
            VAR=$(echo "$K" | tr '[:lower:]' '[:upper:]')
            VAR_VALUE=$(eval "echo \$CTX__${K}")
            if [ ! -z "$VAR_VALUE" ]; then
                # Run the program that handles this custom field
                ${CERNVM_ONLINE_D}/${K} "${VAR_VALUE}"
            fi
        done
    fi
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    
    ## Step 6) Prepare environment and start AMICONFIG configuration script
    export AMICONFIG_CONTEXT_URL="file:${C_PATH}"
    eval $AMICONFIG
    if [ $? -ne 0 ]; then
        [ $SILENT -eq 0 ] && echo "Unable to contextualize the Virtual Machine!" 1>&2
        rm "$TMP_FILE"
        return 1
    fi
    
    ## Remove amiconfig database and restart if that's the first contextualization
    if [ -z "$VM_CONTEXT_NAME" ]; then
        if [ -f /var/lib/raa/raadb ] && [ -f /etc/init.d/raa ]; then
            rm /var/lib/raa/raadb
            /etc/init.d/raa restart
        fi
    fi
    
    ## Step 7) Update local configuration
    CTX_ID="${CTX__VM_CONTEXT_UUID}"
    [ -z "$CTX_ID" ] && CTX_ID="$CONTEXT_KEY"
    update_config "VM_CONTEXT_ID" "'$CTX_ID'"
    update_config "VM_CONTEXT_NAME" "'$CTX__VM_CONTEXT_NAME'"
    
    # Completed :D
    rm "$TMP_FILE"
    return 0
    
}

########################################################################################
#                                   INITIALIZATION                                     #
########################################################################################

# Generate VM uuid if it does not exist
if [ ! -f $VM_CONFIG_FILE ]; then
    
    # Get CernVM UUID or generate a new one
    CERNVM_UUID=$(cat $CERNVM_DEFAULT_CONFIG | grep ^CERNVM_UUID | awk -F= '{print $2}')
    [ -z "$CERNVM_UUID" ] && CERNVM_UUID=$(uuidgen | tr '[A-Z]' '[a-z]')
    
    # Setup config file
    echo "# Virtual machine identification information" >> $VM_CONFIG_FILE
    echo "VM_UUID=$CERNVM_UUID" >> $VM_CONFIG_FILE
    
    # Generate a random salt for various cryprographic operations
    HASH=$(echo $(hostname):$(date):$RANDOM | sha1sum)
    BEGIN=$RANDOM
    let BEGIN%=30
    echo "VM_CRYPTO_SALT=${HASH:$BEGIN:10}" >> $VM_CONFIG_FILE
    
    # Only owner can read or write - others only read
    chmod 0644 "$VM_CONFIG_FILE"
    
fi

# Include the configuration file
. $VM_CONFIG_FILE

########################################################################################
#                                    MAIN SCRIPT                                       #
########################################################################################

# Check the command-line arguents
OP="site"
[ ! -z "$1" ] && OP="$1"

# ==========================================
# Read CernVM's site.conf and fetch the new
# contextualization information from there
# ------------------------------------------
if [ "$OP" == "site" ]; then
# ==========================================
    
    # Check for site.conf
    [ ! -f "$CERNVM_SITE_CONFIG" ] && exit 0
    
    # Include site.conf
    read_conf "$CERNVM_SITE_CONFIG"
    [ -z "$CERNVM_CONTEXTUALIZATION_KEY" ] && exit 0

    # Fetch contextualization information
    CONTEXT_ID=$(echo "$CERNVM_CONTEXTUALIZATION_KEY" | awk -F':' '{print $1}')
    CONTEXT_KEY=$(echo "$CERNVM_CONTEXTUALIZATION_KEY" | awk -F':' '{print $2}')
    
    # Contextualize using context_id
    contextualize "context_id" "$CONTEXT_ID" "$CONTEXT_KEY"
    [ ! $? -eq 0 ] && exit 1
    
    # Completed
    exit 0

# ==========================================
# Display the pairing login screen
# ------------------------------------------
elif [ "$OP" == "login" ]; then
# ==========================================
    
    # Trap Control+C
    trap 'echo -n ""' 2
    
    # Start login screen loop
    while true; do
        
        # Show banner
        clear
        login_banner
        
        # Loop on the credential screen, not to repead the banner
        READING_INPUT=1
        while [ $READING_INPUT -eq 1 ]; do
        
            # Display pin prompt
            echo ""
            NEEDS_REBOOT=0
            if [ ! -z "$VM_CONTEXT_ID" ]; then
                NEEDS_REBOOT=1
                NAME="${VM_CONTEXT_NAME}"
                [ -z "$NAME" ] && NAME="${VM_CONTEXT_ID}"
                echo "Machine contextualized with context: ${NAME}"
                read -p "Instance pairing pin (re-contextualize): " PIN
            else
                read -p "Instance pairing pin: " PIN                
            fi
            KEY=""
        
            # Basic pin validation
            PIN=$(echo "$PIN" | tr -d ' ' | tr -d '-')
            if [ ${#PIN} -ne 6 ]; then
                echo "Invalid pin"
                continue
            fi
        
            # Check if we need also a password
            if [ $(pin_encrypted "${PIN}") -eq 1 ]; then
                read -s -p "Context secret: " KEY
                [ -z "$KEY" ] && echo "Invalid password!" && continue
            fi
            
            # We are ready to perform pairing
            echo "" 1>&2
            contextualize "pin" "$PIN" "$KEY"
            if [ $? -ne 0 ]; then
                sleep 3
            else
                echo "Machine successfully contextualized!"
                
                # Reboot if needed
                [ $NEEDS_REBOOT -eq 1 ] && reboot_prompt
                
                # Change to tty1 :)
                sleep 3
                chvt 1
            fi
            
            # Display banner again
            READING_INPUT=0
        
        done
        
    done
    
# ==========================================
# Download and apply the contextualization
# using the key specified from the command-line
# ------------------------------------------
elif [ "$OP" == "apply" ]; then
# ==========================================

    # Ensure argument presence
    [ -z "$2" ] && echo "Please specify a contextualization key!" 1>&2 && exit 1

    # Fetch contextualization information
    CONTEXT_ID=$(echo "$2" | awk -F':' '{print $1}')
    CONTEXT_KEY=$(echo "$2" | awk -F':' '{print $2}')

    # Contextualize using context_id specified by command-line
    contextualize "context_id" "$CONTEXT_ID" "$CONTEXT_KEY"
    [ ! $? -eq 0 ] && exit 1
    
    # Completed
    exit 0

# ==========================================
# Similar to login but with provided PIN
# ------------------------------------------
elif [ "$OP" == "pair" ]; then
# ==========================================
    [ -z "$2" ] && echo "Please specify a pairing pin!" 1>&2 && exit 1
    PIN=$2
    SECRET="$3"
    contextualize "pin" "$PIN" "$SECRET"

    exit $?


# ==========================================
else
    echo "CernVM Online Contextualization script v0.1"
    echo "ERROR: Unknown operation specified!"
    echo "Usage:"
    echo ""
    echo " cernvm-online.sh site                  - Perform cloud contextualization"
    echo "                                          according to CernVM Site configuration."
    echo " cernvm-online.sh login                 - Display the pairing login screen"
    echo " cernvm-online.sh pair <PIN> [<secret>] - Performs pin pairing"
    echo " cernvm-online.sh apply <uuid[:secret]> - Download and apply the specified"
    echo "                                          contextualization information."
    echo ""
fi
