#!/bin/bash

#####################################################
# Script for the task "CustomizeGuestOS"            #
# Will partition, format and mount additional disks #
# Date: 06/17/2010                                  #
# Author: Anton S                                   #
# Updated: Les Kimmel  23MAR2018                    #
# Added ability to use SWAP, labels, and XFS        #
#####################################################

#source ../scripts/default/Common_Functions.sh || exit 3

FILE_HDR="[VRMAgent:$0]"

#set -x

fnSetupDisk()
{
    #WRK_DISK=/dev/sdb
    WRK_DISK=$1
    #MNT_POINT=/mnt/disk1
    MNT_POINT=$2
    #FS_TYPE=ext3
    FS_TYPE=$3
    #FS_LABEL=fooDisk
    FS_LABEL=$4

    WRK_PART=${WRK_DISK}1

    if [ "$FS_LABEL" != "False" ]
    then
        LABEL_OPT="-L $FS_LABEL"
        DEV_SPEC="LABEL=$FS_LABEL"
    else
        LABEL_OPT=''
        DEV_SPEC="$WRK_PART"
    fi

    if [ "$FS_TYPE" = "swap" ]
    then
        PART_TYPE=82 # Linux Swap
        FS_COMMAND='mkswap'
        DUMP_OPTS='0 0'
    else
        PART_TYPE=83 # Linux
        FS_COMMAND="mkfs.$FS_TYPE"
        DUMP_OPTS='1 2'

        grep $MNT_POINT /etc/fstab
        if [ $? -eq 0 ]; then
            logger "$FILE_HDR $MNT_POINT exist in /etc/fstab. Skip ..."
            echo "$FILE_HDR $MNT_POINT exist in /etc/fstab. Skip ..." >> /usr/share/gugent/echo.out
            return 3
        fi
    fi


    fdisk -l | grep $WRK_PART
    if [ $? -eq 0 ]; then
        logger "$FILE_HDR Requested partition $WRK_PART already exist. Skip ..."
        echo "$FILE_HDR Requested partition $WRK_PART already exist. Skip ..." >> /usr/share/gugent/echo.out
        return 1
    fi

    mount | grep $MNT_POINT
    if [ $? -eq 0 ]; then
        logger "$FILE_HDR $MNT_POINT is already mounted. Skip ..."
        echo "$FILE_HDR $MNT_POINT is already mounted. Skip ..." >> /usr/share/gugent/echo.out
        return 2
    fi

    eval which $FS_COMMAND
    if [ $? -ne 0 ]; then
        logger "$FILE_HDR Unknown FS type: $FS_TYPE. Skip ..."
        echo "$FILE_HDR Unknown FS type: $FS_TYPE. Skip ..." >> /usr/share/gugent/echo.out
        return 4
    fi


#    echo "Creating $WRK_PART as $MNT_POINT with $FS_TYPE FS ..."

fdisk $WRK_DISK << EOF
n
p
1


t
$PART_TYPE
w
EOF

    its_there=0
    for secDelay in 1 2 3 4 5 6 7 8 9 10
    do
        ls /dev/sd* | grep $WRK_PART
        if [ $? -ne 0 ]; then
            sleep 1
        else
            its_there=1
            break
        fi
    done

    if [ $its_there -eq 0 ]; then
        logger "$FILE_HDR fdisk add partition failed. Stop ..."
        echo "$FILE_HDR fdisk add partition failed. Stop ..." >> /usr/share/gugent/echo.out
        return 5
    fi

    #mkfs.$FS_TYPE -v $WRK_PART >> /usr/share/gugent/echo.out
    #mkfs.$FS_TYPE $WRK_PART >> /usr/share/gugent/echo.out
    eval $FS_COMMAND $LABEL_OPT $WRK_PART >> /usr/share/gugent/echo.out

    if [ $? -ne 0 ]; then
        #logger "$FILE_HDR mkfs.$FS_TYPE command failed. Stop ..."
        #echo "$FILE_HDR mkfs.$FS_TYPE command failed. Stop ..." >> /usr/share/gugent/echo.out
        logger "$FILE_HDR $FS_COMMAND command failed. Stop ..."
        echo "$FILE_HDR $FS_COMMAND command failed. Stop ..." >> /usr/share/gugent/echo.out
        return 6
    fi

    if [ "$MNT_POINT" = "swap" ]
    then
        swapon $WRK_PART
    else
        mkdir -p $MNT_POINT
        mount $WRK_PART $MNT_POINT
    fi

    if [ $? -ne 0 ]; then
        logger "$FILE_HDR Warning: cannot mount $WRK_PART as $MNT_POINT ..."
        echo "$FILE_HDR Warning: cannot mount $WRK_PART as $MNT_POINT ..." >> /usr/share/gugent/echo.out
    fi

    echo "$DEV_SPEC         $MNT_POINT              $FS_TYPE        defaults        ${DUMP_OPTS}" >> /etc/fstab

    logger "$FILE_HDR Done creating $WRK_PART as $MNT_POINT with $FS_TYPE FS ..."
    echo "$FILE_HDR Done creating $WRK_PART as $MNT_POINT with $FS_TYPE FS ..." >> /usr/share/gugent/echo.out
}


i=1
for disk in `ls -1 /dev/sd[b-z]`
do
    PropertyName=VirtualMachine.Disk$i.Letter
    echo $PropertyName
    PropertyValue=$(python getprop.py $PropertyName)
    mpt=$PropertyValue
    echo $PropertyValue

    if [ "$mpt" != "False" ]; then
        PropertyValue=$(python getprop.py VirtualMachine.Disk$i.Filesystem)
        echo $PropertyValue
        fs=$PropertyValue
        PropertyValue=$(python getprop.py VirtualMachine.Disk$i.Label)
        echo $PropertyValue
        lbl=$PropertyValue
        echo $fs
        if [ "$fs" = "False" ]; then
            fs="ext3"
            echo "set fs"
        fi

        [ ! -z "$lbl" ] && lbl_text="(LABEL=$lbl)" || lbl_text=''
        logger "$FILE_HDR Trying to create $disk as $mpt with $fs FS ${lbl_text}..."
        echo "$FILE_HDR Trying to create $disk as $mpt with $fs FS ${lbl_text}..." >> /usr/share/gugent/echo.out

        fnSetupDisk $disk $mpt $fs $lbl
    fi

    (( i += 1 ))
done
