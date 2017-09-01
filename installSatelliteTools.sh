#!/bin/bash
#Name: Install Satellite Tools
#Creators: Kasey Linden / Les Kimmel
#Version: v2.0

###CONFIGURATION####
#SATELLITE VARIBLES#
#VARIABLES ARE ONLY USED FOR SCRIPT EXECUTION OUTSIDE OF VRA. VRA PROVIDES VARIABLES VIA SOFTWARE COMPONENT.
#CHECK FOR ENVIRONMENT VARIABLES SET BY VRA SOFTWARE COMPONENT ELSE USE DEFAULTS
activation_key=${SAT_ACTIVATION_KEY:-"activationKey"}
satellite_organization=${SAT_ORGANIZATION:-"company"}
satellite_server=${SAT_SERVER:-"satelliteServer"}
puppet_environment=${SAT_PUPPET_ENV:-"puppetEnvironment"}
satellite_tools_repository=${SAT_TOOLS_REPO:-"rhel-7-server-satellite-tools-6.2-rpms"}
consumer_key="http://${satellite_server}/pub/katello-ca-consumer-latest.noarch.rpm"
####################

rollback_subscribe() {
    msg=
    echo ${msg+"Unregistering from Satellite server"}
    subscription-manager unregister
    check_rc $? 0 "${msg}" 1
    echo ${msg+"Removing local subscription information"}
    subscription-manager clean
    check_rc $? 0 "${msg}" 1
}

rollback_attach() {
    echo ${msg+"Removing all current subscriptions"}
    subscription-manager remove --all
    check_rc $? 0 "${msg}" 1
}

cleanup() {
    case ${1} in
        2)
            rollback_subscribe
            ;;
        3)
            rollback_attach
            ;;
    esac
    
    cursor=$(( ${1} - 1 ))
    [ ${cursor} -gt 0 ] && cleanup ${cursor}
}

check_rc() {
    if [ ${1} -ne ${2} ]
    then
        echo "Failed during step: ${3}"
        cleanup ${4}
        exit ${4}
    fi
}

#Install Katello CA Package
yum localinstall --nogpgcheck -y "${consumer_key}"
check_rc $? 0 "Installing consumer key" 1

#Regsiter Server to Satellite Server
echo ${msg:="Registering to Satellite server"}
subscription-manager register --org $satellite_organization --activationkey $activation_key
check_rc $? 0 "${msg}" 2; unset msg
echo ${msg:="Attaching Red Hat subscription(s)"}
subscription-manager attach --auto
subscription-manager list | grep "^Status:" | grep -i "unknown"
check_rc $? 1 "${msg}" 3; unset msg

#Enable Repositories
#THESE MAY BE ALREADY ENABLED BY THE ACTIVATION KEY
subscription-manager repos --list-enabled | grep "^Repo ID:" | grep -i "${satellite_tools_repository}"
rc=$?
if [ $rc -ne 0  ]
then
    echo ${msg:="Enabling Satellite Tools repository"}
    subscription-manager repos --enable ${satellite_tools_repository}
    check_rc $? 0 "${msg}" 4; unset msg
fi

#Install Katello Agent
rpm -qi 'katello-agent'
rc=$?
if [ $rc -ne 0 ]
then
    echo ${msg:="Installing Katello Agent"}
    yum install katello-agent -y 
    check_rc $? 0 "${msg}" 5; unset msg
fi

#Install Puppet Agent
rpm -qi 'puppet'
rc=$?
if [ $rc -ne 0 ] ; then
    echo ${msg:="Installing Puppet Agent"}
    yum install puppet -y
    check_rc $? 0 "${msg}" 6; unset msg
fi

#Update Puppet File Config  with Puppet Config
echo ${msg:="Configuring Puppet Agent"}
puppet config set ca_server $satellite_server --section agent && \
puppet config set server $satellite_server --section agent #&& \
#puppet config set environment $puppet_environment --section agent
check_rc $? 0 "${msg}" 7;unset msg

#Enable and Start Services
echo ${msg:="Enabling and starting services"}
systemctl enable goferd && \
systemctl enable puppet && \
systemctl start goferd && \
systemctl start puppet
check_rc $? 0 "${msg}" 8; unset msg

