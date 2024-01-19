#!/bin/bash

print_help() {
    echo ""
    echo "Exclude specific ModSec rule per username or domain in cPanel"
    echo "Usage: $PROGNAME [-a|--add][-del|--delete][--by-username][--by-domain][-u|--username  <username>][-d|--domain <domain_name>] [r|--rule <modsec-rule-id>]"
    echo ""
}
ADD=0
DELETE=0
REBUILD=0
RESTART=0
CAN_REBUILD_OR_RESTART=0
##              Exclude Method           ##
# 0: By Username (default)                #
# 1: By Domain                            #
# 2: Both                                 #

EXCLUDE_METHOD=0

rebuild_or_restart() {
    REBUILD=$(echo "$1" | cut -d"," -f1 | cut -d"=" -f2)
    RESTART=$(echo "$1" | cut  -d"," -f2 | cut -d"=" -f2)

    if [ $REBUILD -eq 1 ]; then
        echo "=| Rebuild httpd conf"
        result=$(/scripts/rebuildhttpdconf 2>&1)
        if [ $? -ne 0 ]; then
            error_message=$(echo -e "$result" | grep "httpd:")
            echo -e "Warning: rebuildhttpdconf failed with the error:\n$error_message"
            exit 1
        fi
        echo "=| Built /etc/apache2/conf/httpd.conf OK"
    fi
    if [ $RESTART -eq 1 ] && [ $REBUILD -eq 0 ]; then
        echo "=| Rebuild httpd conf"
        result=$(/scripts/rebuildhttpdconf 2>&1)
        if [ $? -ne 0 ]; then
            error_message=$(echo "$result" | grep "httpd:")
            echo -e "Warning: rebuildhttpdconf failed with the error:\n$error_message"
            exit 1
        else
            /scripts/restartsrv_httpd > /dev/null 2>&1
        fi
        echo "=| httpd started successfully"
    elif [ $RESTART -eq 1 ] && [ $REBUILD -eq 1 ]; then
        echo "=| Restart httpd"
        result=$(/scripts/restartsrv_httpd 2>&1)
        if [ $? -ne 0 ]; then
            error_message=$(echo "$result" | grep "httpd:")
            echo -e "Warning: restartsrvhttpd failed with the error:\n$error_message"
            exit 1
        fi
        echo "=| httpd started successfully"
    fi
}

if [ -z "$1" ]; then
    echo "Warning: argument is empty!"
    print_help
    exit 1
fi

while test -n "$1"; do
    case "$1" in
        --help)
            print_help
            exit 0
            ;;
        -h)
            print_help
            exit 0
            ;;
        --add)
            ADD=1
            ;;
        -a)
            ADD=1
            ;;
        --delete)
            DELETE=1
            ;;
        -del)
            DELETE=1
            ;;
        --by-username)
            BY_USERNAME=1
            ;;
        --by-domain)
            BY_DOMAIN=1
            ;;
        --username)
            username=$2
            shift
            ;;
        -u)
            username=$2
            shift
            ;;
        --domain)
            domain_name=$2
            shift
            ;;
        -d)
            domain_name=$2
            shift
            ;;
        --rule)
            rule_id="$2"
            shift
            ;;
        -r)
            rule_id="$2"
            shift
            ;;
        --rebuild)
            REBUILD=1
            ;;
        --restart)
            RESTART=1
            ;;
        *)
            echo "Unknown argument: $1"
            print_help
            exit 3
    esac
    shift
done


if [ ! -z "$BY_USERNAME" ] && [ ! -z "$BY_DOMAIN" ]; then
    if [ $BY_USERNAME -eq 1 ] && [ $BY_DOMAIN -eq 1 ]; then
        EXCLUDE_METHOD=2
    fi
elif [ ! -z "$BY_USERNAME" ]; then
    if [ $BY_USERNAME -eq 1 ]; then
        EXCLUDE_METHOD=0
    fi
elif [ ! -z "$BY_DOMAIN" ]; then
    if [ $BY_DOMAIN -eq 1 ]; then
        EXCLUDE_METHOD=1
    fi
fi
#create std directory with reference of https://support.cpanel.net/hc/en-us/articles/4403595742487-How-to-disable-a-mod-security-rule-on-a-per-user-basis-
if [ ! -d "/etc/apache2/conf.d/userdata" ]; then
    mkdir -p /etc/apache2/conf.d/userdata/std/2_4
    chmod 755 /etc/apache2/conf.d/userdata
    find /etc/apache2/conf.d/userdata -type d -exec chmod 755 {} +
fi



if [ $ADD -eq 1 ]; then
    if [ $EXCLUDE_METHOD  -eq 0 ]; then
        #check if rule id empty
        if [ -z  "$rule_id" ]; then
            echo "Warning: rule id empty, please provide rule id with option -r or --rule!"
            exit 1
        fi

        #declare array of rule id
        declare -a rule_id_array
        sec_rule_remove_id=""
        #declare -a past_rule_id_array
        
        rule_file="/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
        # if [ -s "$rule_file" ]; then
        #     # get all past rule id
        #     all_rule_id=$(grep -oE "[[:digit:]]+$" modsec.conf  | sort -u | tr "\n" " ")
        #     past_rule_id_array=($(echo "${all_rule_id/ /"  "}"))
        #     unset
        # fi

        #create one or multiple SecRuleRemoveById with the rule_ids
        if [[ $rule_id =~ ^[[:digit:]]+$ ]]; then
            # check if exclude rule conf file not empty
            if [ -s "$rule_file" ]; then
                # if rule_file not empty and there is no inputted rule_id inside rule_file then append rule_id to rule_file
                if [[ ! $(cat "$rule_file") =~ $rule_id ]]; then 
                    all_rule_id=$(grep -oE "[[:digit:]]+$" $rule_file  | sort -u | tr "\n" " ")
                    rule_id_array=($(echo "${all_rule_id/ /"  "}"))
                    unset all_rule_id

                    rule_id_array+=($rule_id)
                    for (( r=0; r<${#rule_id_array[@]}; r++)); do
                        sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                        if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                            sec_rule_remove_id+="\n"
                        fi
                    done
                else
                    echo "Warning: rule id $rule_id is already available in $rule_file!"
                fi
            else
                sec_rule_remove_id="SecRuleRemoveById $rule_id"
            fi
        elif [[ $rule_id =~ ^[[:digit:]]+[[:space:]][[:digit:]]+$ ]]; then
            # check if rule file not empty; then add the past rule id to rule_id_array and append the inputted rule id to rule_id_array
            # if rule file empty, only add the inputted rule id to rule_id_array
            if [ -s "$rule_file" ]; then
                all_rule_id=$(grep -oE "[[:digit:]]+$" $rule_file  | sort -u | tr "\n" " ")
                rule_id_array=($(echo "${all_rule_id/ /"  "}"))
                unset all_rule_id

                rule_id_array+=($(echo "${rule_id/ /"  "}"))
            else
                rule_id_array=($(echo "${rule_id/ /"  "}"))
            fi

            #loop thorugh rule_id_array then create SecRuleRemoveById based on that
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        elif [[ $rule_id =~ ^[[:digit:]]+,[[:digit:]]+$ ]]; then
            # check if rule file not empty; then add the past rule id to rule_id_array and append the inputted rule id to rule_id_array
            # if rule file empty, only add the inputted rule id to rule_id_array
            if [ -s "$rule_file" ]; then
                all_rule_id=$(grep -oE "[[:digit:]]+$" $rule_file  | sort -u | tr "\n" " ")
                rule_id_array=($(echo "${all_rule_id/ /"  "}"))
                unset all_rule_id

                rule_id_array+=($(echo "${rule_id/,/"  "}"))
            else
                rule_id_array=($(echo "${rule_id/,/"  "}"))
            fi
            
            #loop thorugh rule_id_array then create SecRuleRemoveById based on that
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        else
            echo "Unknown rule_id delimiter, can only use comma and space!"
            exit 1
        fi

        # check if username or domain_name empty
        if [ -n "$username" ]; then
            echo "-= Start exclude the rule below for username $username"
            echo -e "$sec_rule_remove_id"
            [ ! -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && mkdir "/etc/apache2/conf.d/userdata/std/2_4/$username"
cat <<EOF>"$rule_file"
<IfModule mod_security2.conf>
$(echo -e "$sec_rule_remove_id")
<LocationMatch .*>
$(echo -e "$sec_rule_remove_id")
</LocationMatch>
</IfModule>
EOF
            #Tidy up the config
            sed -i -E "s/^(SecRuleRemoveById .*)/   \1/g" "$rule_file"
            find /etc/apache2/conf.d/userdata -type d -exec chmod 755 {} +
            find /etc/apache2/conf.d/userdata -type f -exec chmod 644 {} +
            echo "-= Exclude rule done"

            rebuild_or_restart "REBUILD=$REBUILD,RESTART=$RESTART"
        else
            echo "Warning: need username, need to define it by using -u!"
            exit 1
        fi
    # define mechanism exclude by using both domain and username
    elif [ $EXCLUDE_METHOD -eq 1 ]; then
        #check if rule id empty
        if [ -z  "$rule_id" ]; then
            echo "Warning: rule id empty, please provide rule id with option -r or --rule!"
            exit 1
        fi

        #declare array of rule id
        declare -a rule_id_array
        sec_rule_remove_id=""

        rule_file="/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
        
        #create one or multiple SecRuleRemoveById with the rule_ids
        if [[ $rule_id =~ ^[[:digit:]]+$ ]]; then
            # check if exclude rule conf file not empty
            if [ -s "$rule_file" ]; then
                # if rule_file not empty and there is no inputted rule_id inside rule_file then append rule_id to rule_file
                if [[ ! $(cat "$rule_file") =~ $rule_id ]]; then 
                    all_rule_id=$(grep -oE "[[:digit:]]+$" $rule_file  | sort -u | tr "\n" " ")
                    rule_id_array=($(echo "${all_rule_id/ /"  "}"))
                    unset all_rule_id

                    rule_id_array+=($rule_id)
                    for (( r=0; r<${#rule_id_array[@]}; r++)); do
                        sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                        if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                            sec_rule_remove_id+="\n"
                        fi
                    done
                else
                    echo "Warning: rule id $rule_id is already available in $rule_file!"
                fi
            else
                sec_rule_remove_id="SecRuleRemoveById $rule_id"
            fi
        elif [[ $rule_id =~ ^[[:digit:]]+[[:space:]][[:digit:]]+$ ]]; then
            # check if rule file not empty; then add the past rule id to rule_id_array and append the inputted rule id to rule_id_array
            # if rule file empty, only add the inputted rule id to rule_id_array
            if [ -s "$rule_file" ]; then
                all_rule_id=$(grep -oE "[[:digit:]]+$" $rule_file  | sort -u | tr "\n" " ")
                rule_id_array=($(echo "${all_rule_id/ /"  "}"))
                unset all_rule_id

                rule_id_array+=($(echo "${rule_id/ /"  "}"))
            else
                rule_id_array=($(echo "${rule_id/ /"  "}"))
            fi

            #loop thorugh rule_id_array then create SecRuleRemoveById based on that
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        elif [[ $rule_id =~ ^[[:digit:]]+,[[:digit:]]+$ ]]; then
            # check if rule file not empty; then add the past rule id to rule_id_array and append the inputted rule id to rule_id_array
            # if rule file empty, only add the inputted rule id to rule_id_array
            if [ -s "$rule_file" ]; then
                all_rule_id=$(grep -oE "[[:digit:]]+$" $rule_file  | sort -u | tr "\n" " ")
                rule_id_array=($(echo "${all_rule_id/ /"  "}"))
                unset all_rule_id

                rule_id_array+=($(echo "${rule_id/,/"  "}"))
            else
                rule_id_array=($(echo "${rule_id/,/"  "}"))
            fi
            
            #loop thorugh rule_id_array then create SecRuleRemoveById based on that
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        else
            echo "Unknown rule_id delimiter, can only use comma and space!"
            exit 1
        fi

        if [ -n "$domain_name" ]; then
            if [ -z "$username" ]; then
                username=$(/scripts/whoowns "$domain_name")
            fi

            echo "-= Start exclude the rule below for $domain_name"
            echo -e "$sec_rule_remove_id"

            [ ! -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && mkdir -p "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name"
cat <<EOF>"$rule_file"
<IfModule mod_security2.conf>
$(echo -e "$sec_rule_remove_id")
<LocationMatch .*>
$(echo -e "$sec_rule_remove_id")
</LocationMatch>
</IfModule>
EOF
            #Tidy up the config
            sed -i -E "s/^(SecRuleRemoveById .*)/   \1/g" "$rule_file"
            find /etc/apache2/conf.d/userdata -type d -exec chmod 755 {} +
            find /etc/apache2/conf.d/userdata -type f -exec chmod 644 {} +
            echo "-= Exclude rule done"

            rebuild_or_restart "REBUILD=$REBUILD,RESTART=$RESTART"
        else
            echo "Warning: need domain_name, need to define it by using -d!"
            exit 1
        fi
    elif [ $EXCLUDE_METHOD -eq 2 ]; then
        #check if rule id empty
        if [ -z  "$rule_id" ]; then
            echo "Warning: rule id empty, please provide rule id with option -r or --rule!"
            exit 1
        fi

        #declare array of rule id
        declare -a rule_id_array
        sec_rule_remove_id=""

        #create one or multiple SecRuleRemoveById with the rule_ids
        if [[ $rule_id =~ ^[[:digit:]]+$ ]]; then
            sec_rule_remove_id="SecRuleRemoveById $rule_id"
        elif [[ $rule_id =~ ^[[:digit:]]+[[:space:]][[:digit:]]+$ ]]; then
            rule_id_array=($(echo "${rule_id/ /"  "}"))
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        elif [[ $rule_id =~ ^[[:digit:]]+,[[:digit:]]+$ ]]; then
            rule_id_array=($(echo "${rule_id/,/"  "}"))
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        else
            echo "Unknown rule_id delimiter, can only use comma and space!"
            exit 1
        fi

        if [ -z "$username" ] && [ -z "$domain_name" ]; then
            echo "Warning: need to define both username and domain_name by using option -d and -u!"
            exit 1
        fi


        echo "-= Start exclude the rule below for $username"
        echo -e "$sec_rule_remove_id"

        [ ! -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && mkdir "/etc/apache2/conf.d/userdata/std/2_4/$username"
cat <<EOF>"/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
<IfModule mod_security2.conf>
$(echo -e "$sec_rule_remove_id")
<LocationMatch .*>
$(echo -e "$sec_rule_remove_id")
</LocationMatch>
</IfModule>
EOF
        #Tidy up the config
        sed -i -E "s/^(SecRuleRemoveById .*)/   \1/g" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
        find /etc/apache2/conf.d/userdata -type d -exec chmod 755 {} +
        find /etc/apache2/conf.d/userdata -type f -exec chmod 644 {} +
        echo "-= Exclude rule done"

        if [ -z "$username" ]; then
            username=$(/scripts/whoowns "$domain_name")
        fi
        echo "-= Start exclude the rule for $domain_name"
        echo -e "$sec_rule_remove_id"

        [ ! -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && mkdir -p "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name"
cat <<EOF>"/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
<IfModule mod_security2.conf>
$(echo -e "$sec_rule_remove_id")
<LocationMatch .*>
$(echo -e "$sec_rule_remove_id")
</LocationMatch>
</IfModule>
EOF
        #Tidy up the config
        sed -i -E "s/^(SecRuleRemoveById .*)/   \1/g" "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
        find /etc/apache2/conf.d/userdata -type d -exec chmod 755 {} +
        find /etc/apache2/conf.d/userdata -type f -exec chmod 644 {} +
        echo "-= Exclude rule done"


        rebuild_or_restart "REBUILD=$REBUILD,RESTART=$RESTART"
    else
        echo "Warning: need to define --by-username, --by-domain, or both!"
        exit 1
    fi


elif [ $DELETE -eq 1 ]; then
    if [ -n "$rule_id" ]; then
        #declare array of rule id
        declare -a rule_id_array
        sec_rule_remove_id=""

        #create one or multiple SecRuleRemoveById with the rule_ids
        if [[ $rule_id =~ ^[[:digit:]]+$ ]]; then
            rule_id_array[0]=$rule_id
        elif [[ $rule_id =~ ^[[:digit:]]+[[:space:]][[:digit:]]+$ ]]; then
            rule_id_array=($(echo "${rule_id/ /"  "}"))
        elif [[ $rule_id =~ ^[[:digit:]]+,[[:digit:]]+$ ]]; then
            rule_id_array=($(echo "${rule_id/,/"  "}"))
        else
            echo "Unknown rule_id delimiter, can only use comma and space!"
            exit 1
        fi
       
    fi

    if [ -n "$username" ] && [ -n "$domain_name" ]; then
        if [ -z "$rule_id" ]; then
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf" ]; then
                echo "-| Delete file /etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
                rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
                echo "-| File deleted"
                CAN_REBUILD_OR_RESTART=1
            else
                echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf not found!"
            fi
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf" ]; then
                echo "-| Delete file /etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
                rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
                echo "-| File deleted"
                CAN_REBUILD_OR_RESTART=1
            else
                echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf not found!"
            fi
        else
            for r in ${rule_id_array[@]}; do
                if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf" ]; then
                    echo "-| Delete rule id $r from excluded rule config for $username"
                    sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
                    echo "-| Rule deleted from excluded rule config for $username"
                    CAN_REBUILD_OR_RESTART=1
                else
                    echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf not found!"
                fi
                if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf" ]; then
                    echo "-| Delete rule id $r from excluded rule config for $domain_name"
                    sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
                    echo "-| Rule deleted from excluded rule config for $domain_name"
                    CAN_REBUILD_OR_RESTART=1
                else
                    echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf not found!"
                fi
            done
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf" ]; then
                sed -i '/^   $/d' "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
            fi
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf" ]; then
                sed -i '/^   /d' "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
            fi
        fi
        [ $CAN_REBUILD_OR_RESTART -eq 1 ] && rebuild_or_restart "REBUILD=$REBUILD,RESTART=$RESTART"
        

    elif [ -n "$username" ]; then
        if [ -z "$rule_id" ]; then
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf" ]; then
                echo "=| Delete file /etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
                rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
                echo "=| File deleted"
                CAN_REBUILD_OR_RESTART=1
            else
                echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf not found!"
            fi
        else
            for r in ${rule_id_array[@]}; do
                if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf" ]; then
                    echo "-| Delete rule id $r from excluded rule config for $username"
                    sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
                    echo "-| Rule deleted from excluded rule config for $username"
                    CAN_REBUILD_OR_RESTART=1
                else
                    echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf not found!"
                fi
            done
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf" ]; then
                sed -i '/^   $/d' "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
            fi
        fi
        [ $CAN_REBUILD_OR_RESTART -eq 1 ] && rebuild_or_restart "REBUILD=$REBUILD,RESTART=$RESTART"
    elif [ -n "$domain_name" ]; then
        [ -z "$username" ] && username=$(/scripts/whoowns "$domain_name")
        if [ -z "$rule_id" ]; then
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf" ]; then
                echo "-| Delete file /etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
                rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
                echo "-| File deleted"
                CAN_REBUILD_OR_RESTART=1
            else
                echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf not found!"
            fi
        else
            for r in ${rule_id_array[@]}; do
                if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf" ]; then
                    echo "-| Delete rule id $r from excluded rule config for $domain_name"
                    sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
                    echo "-| Rule deleted from excluded rule config for $domain_name"
                    CAN_REBUILD_OR_RESTART=1
                else
                    echo "File /etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf not found!"
                fi
            done
            if [ -d "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name" ] && [ -f "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf" ]; then
                sed -i '/^   $/d' "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
            fi
        fi
        [ $CAN_REBUILD_OR_RESTART -eq 1 ] && rebuild_or_restart "REBUILD=$REBUILD,RESTART=$RESTART"
    else
        echo "Warning: domain_name and username empty. Need to define -d, -u, or both!"
        exit 1
    fi
else
    echo "Warning: need to use argument -a or -del!"
    exit 1
fi