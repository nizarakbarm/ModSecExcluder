#!/bin/bash

print_help() {
    echo ""
    echo "Exclude specific ModSec rule per username or domain in cPanel"
    echo "Usage: $PROGNAME [-u|--username  <username>][-d|--domain <domain_name>] [r|--rule <modsec-rule-id>]"
    echo ""
}

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

#create std directory with reference of https://support.cpanel.net/hc/en-us/articles/4403595742487-How-to-disable-a-mod-security-rule-on-a-per-user-basis-
if [ ! -d "/etc/apache2/conf.d/userdata" ]; then
    mkdir -p /etc/apache2/conf.d/userdata/std/2_4
    chmod 755 /etc/apache2/conf.d/userdata
    find /etc/apache2/conf.d/userdata -exec chmod 755 {} +
fi

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
if [ -n "$username" ] || [ -n "$domain_name" ]; then
    :
else
    echo "Warning: need username or domain_name, need to define one of it by using -u or -d!"
    exit 1
fi

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

    echo "-= Exclude rule per username done"
fi