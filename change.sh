#!/bin/bash

FILENAME="$1"

while read line
do
    SERVER=$(echo -e $line | awk '{print $1}')
    echo -e "Server Name = $SERVER"

    PRIVATE_IP=$(echo -e $line | awk '{print $2}')
    echo -e "Private IP = $PRIVATE_IP"

    USER=$(echo -e $line | awk '{print $3}')
    echo -e "User Name = $USER"
    
    PORT=$(echo -e $line | awk '{print $4}')
    echo -e "SSH Port = $PORT"
    
    KEY=$(echo -e $line | awk '{print $5}')
    echo -e "KEY File Name = $KEY"

    NEWKEY=$(echo -e $line | awk '{print $6}')
    echo -e "New-Key File Name = $NEWKEY"

    KEYVALUE=$(ssh-keygen -y -f $NEWKEY)
    echo -e "Changing '$SERVER' key value"
    echo $KEYVALUE

    if [ "" != "$KEYVALUE" ]; then
        sudo echo $KEYVALUE | ssh -o StrictHostKeyChecking=no -i $KEY $USER@$PRIVATE_IP -p $PORT "sudo runuser -l $USER -c 'cat > /home/$USER/.ssh/authorized_keys'"
    else
        echo "invaild keyvalue"
        exit
    fi
    echo -e "$SERVER keychanged"
    echo -e ""
    sleep 3

done < $FILENAME
