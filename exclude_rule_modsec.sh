#!/bin/bash

print_help() {
    echo ""
    echo "Exclude specific ModSec rule per username or domain in cPanel"
    echo "Usage: $PROGNAME [-a|--add][-d|--delete][-u|--username  <username>][-d|--domain <domain_name>] [r|--rule <modsec-rule-id>]"
    echo ""
}
ADD=0
DELETE=0

##              Exclude Method           ##
# 0: By Username (default)                #
# 1: By Domain                            #
# 2: Both                                 #

EXCLUDE_METHOD=0
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
            shift
            ;;
        -a)
            ADD=1
            shift
            ;;
        --delete)
            DELETE=1
            shift
            ;;
        -d)
            DELETE=1
            shift
            ;;
        --by-username)
            BY_USERNAME=1
            shift
            ;;
        --by-domain)
            BY_DOMAIN=1
            shift
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
        *)
            echo "Unknown argument: $1"
            print_help
            exit 3
    esac
    shift
done

if [ $BY_USERNAME -eq 1 ] && [ $BY_DOMAIN -eq 1 ]; then
    EXCLUDE_METHOD=2
elif [ $BY_USERNAME -eq 1 ]; then
    EXCLUDE_METHOD=0
elif [ $BY_DOMAIN -eq 1 ]; then
    EXCLUDE_METHOD=1
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

        #create one or multiple SecRuleRemoveById with the rule_ids
        if [[ $rule_id =~ [[:digit:]]+[[:space:]][[:digit:]] ]]; then
            rule_id_array=($(echo "${rule_id/ /"  "}"))
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        elif [[ [[:digit:]]+,[[:digit:]]+ ]]; then
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
        echo -e "$sec_rule_remove_id"

        # check if username or domain_name empty
        if [ -n "$username" ]; then
            echo "-= Start exclude rule per username"
            mkdir "/etc/apache2/conf.d/userdata/std/2_4/$username"
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
            echo "-= Exclude rule per username done"
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

        #create one or multiple SecRuleRemoveById with the rule_ids
        if [[ $rule_id =~ [[:digit:]]+[[:space:]][[:digit:]] ]]; then
            rule_id_array=($(echo "${rule_id/ /"  "}"))
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        elif [[ [[:digit:]]+,[[:digit:]]+ ]]; then
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
        echo -e "$sec_rule_remove_id"

        if [ -n "$domain_name" ]; then
            if [ -z "$username" ]; then
                username=$(/scripts/whoowns "$domain_name")
            fi

            echo "-= Start exclude rule per domain"
            mkdir -p "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name"
cat <<EOF>"/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
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
            echo "-= Exclude rule per domain done"
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
        if [[ $rule_id =~ [[:digit:]]+[[:space:]][[:digit:]] ]]; then
            rule_id_array=($(echo "${rule_id/ /"  "}"))
            for (( r=0; r<${#rule_id_array[@]}; r++)); do
                sec_rule_remove_id+="SecRuleRemoveById ${rule_id_array[$r]}"
                if [ -n "${rule_id_array[$(( $r + 1 ))]}" ]; then
                    sec_rule_remove_id+="\n"
                fi
            done
        elif [[ [[:digit:]]+,[[:digit:]]+ ]]; then
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
        echo -e "$sec_rule_remove_id"

        if [ -z "$username" ] && [ -z "$domain_name" ]; then
            echo "Warning: need to define both username and domain_name by using option -d and -u!"
            exit 1
        fi


        echo "-= Start exclude rule per username"
        mkdir "/etc/apache2/conf.d/userdata/std/2_4/$username"
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
        echo "-= Exclude rule per username done"

        if [ -z "$username" ]; then
            username=$(/scripts/whoowns "$domain_name")
        fi
        echo "-= Start exclude rule per domain"
        mkdir -p "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name"
cat <<EOF>"/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
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
        echo "-= Exclude rule per domain done"

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
        if [[ $rule_id =~ [[:digit:]]+[[:space:]][[:digit:]] ]]; then
            rule_id_array=($(echo "${rule_id/ /"  "}"))
        elif [[ [[:digit:]]+,[[:digit:]]+ ]]; then
            rule_id_array=($(echo "${rule_id/,/"  "}"))
        else
            echo "Unknown rule_id delimiter, can only use comma and space!"
            exit 1
        fi
        echo -e "$sec_rule_remove_id"
    fi

    if [ -n "$username"] && [ -n "$domain_name" ]; then
        if [ -z "$rule_id" ]; then
            rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
            rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
        else
            for r in ${rule_id_array[@]}; then
                sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
                sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
            done
            sed -i "/^$/d" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
            sed -i "/^$/d" "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
        fi

    elif [ -n "$username" ]; then
        if [ -z "$rule_id" ]; then
            rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
        else
            for r in ${rule_id_array[@]}; then
                sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
            done
            sed -i "/^$/d" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
        fi
    elif [ -n "$domain" ]; then
        if [ -z "$rule_id" ]; then
            rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
        else
            for r in ${rule_id_array[@]}; then
                sed -i "s/SecRuleRemoveById $r//g" "/etc/apache2/conf.d/userdata/std/2_4/$username/$domain_name/modsec.conf"
            done
            sed -i "/^$/d" "/etc/apache2/conf.d/userdata/std/2_4/$username/modsec.conf"
        fi
    else
        echo "Warning: domain_name and username empty. Need to define -d, -u, or both!"
        exit 1
    fi
fi
