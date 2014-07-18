#!/bin/bash
########################################################
# Suricata, Elastic Search, Kibana & Logstash          #
# install script for Ubuntu server 14.04, x64          #
#                                                      #
# v0.37 by t3ChN0M4G3, 2014-07-13                      #
########################################################

# Let's log for the beauty of it
set -e
exec 2> >(tee "install.err")
exec > >(tee "install.log")

# Let's set some vars
myETH="NIC"
myRED="tput setaf 1"
myWHT="tput setaf 7"
mySURICATAVERSION="2.0.2"
myKIBANA="https://download.elasticsearch.org/kibana/kibana/kibana-3.1.0.tar.gz"
myELASTIC="https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.2.2.deb"
myLOGSTASH="https://download.elasticsearch.org/logstash/logstash/packages/debian/logstash_1.4.2-1-2c0f5a1_all.deb"

# Let's make sure there is a warning if running for a second time
if [ -f install.log ];
  then $myRED; echo "### Running more than once may complicate things. Erase install.log if you are really sure."; $myWHT;
  exit 1;
fi

# Let's ask for NIC and check existence
while [ "$(ifconfig -s $myETH | grep $myETH -c)" != "1" ]
do
  ifconfig -s
  $myRED; echo -n "### Which interface should this sensor be associated with? [eth0] "; read myETH; $myWHT;
  if [ "$myETH" = "" ]; then
    myETH="eth0";
  fi
  if [ "$(ifconfig -s $myETH | grep $myETH -c)" = "1" ];
    then $myRED; echo "### Using "$myETH; $myWHT;
    else $myRED; echo "### Could not find "$myETH" please try again."; $myWHT;
  fi
done

# Let's ask for web user and password and create htdigest-md5 output
while [ "$myMORE" != "no" ]
do
  myWEBPASSWD1=""
  myWEBPASSWD2=""
  myWEBPASSWD=""
  myWEBUSER=""
  while true
  do
    $myRED; echo -n "### Please enter web user name: "; read myWEBUSER; $myWHT;
      if [ "$myWEBUSER" = "" ];
       then $myRED; echo "### Web user name may not be blank. "; $myWHT;
       else break
      fi
  done
  while true
  do
    while true
    do
      $myRED; echo -n "### Please enter web user password: "; read -s myWEBPASSWD1; $myWHT; echo "";
        if [ "$myWEBPASSWD1" = "" ]; 
          then $myRED; echo "### Web user password name may not be blank. "; $myWHT;
          else break
        fi
    done
    $myRED; echo -n "### Please re-enter web user password: "; read -s myWEBPASSWD2; $myWHT; echo "";
      if [ "$myWEBPASSWD1" != "$myWEBPASSWD2" ]; 
        then $myRED; echo "### Passwords do not match."; $myWHT;
        else break;
      fi
  done
  myWEBPASSWD="$myWEBPASSWD1"
# Let's rebuild what htdigest does since it does not support a password option
  tee -a myNSM.pwd <<EOF
  $(echo -n "$myWEBUSER:myNSM:" && echo -n "$myWEBUSER:myNSM:$myWEBPASSWD" | md5sum | awk '{print $1}')
EOF
  while true;
  do
    $myRED; echo -n "### Add another user? [yes/no] "; read myMORE; $myWHT;
    if [ "$myMORE" = "yes" -o "$myMORE" = "no" ] 
      then break;
    fi
  done
done

# Let's add the suricata PPA
$myRED; echo "### Adding suricata repository."; $myWHT
add-apt-repository ppa:oisf/suricata-stable -y

# Let's pull some updates
$myRED; echo "### Pulling Updates."; $myWHT
apt-get update -y
$myRED; echo "### Installing Updates."; $myWHT
apt-get dist-upgrade -y

# Let's install all the packages we need
$myRED; echo "### Installing packages."; $myWHT
apt-get install ntp openssl suricata oinkmaster ethtool apache2 apache2-utils openjdk-7-jdk openjdk-7-jre-headless -y
wget $myKIBANA
wget $myELASTIC
wget $myLOGSTASH
tar -C /var/www/ -xzf kibana-3.1.0.tar.gz
mv /var/www/kibana-3.1.0/ /var/www/kibana/
dpkg -i elasticsearch-1.2.2.deb
dpkg -i logstash_1.4.2-1-2c0f5a1_all.deb

# Check for supported suricata version
$myRED; echo "### Checking for supported suricata version."; $myWHT
if [ "$($(which suricata) -V | grep $mySURICATAVERSION -c)" = "1" ];
  then $myRED; echo "### Found supported surricata installation."; $myWHT;
  else $myRED; echo "### Something went wrong, this version of suricata is not supported. Found v"$mySURICATAVERSION"."; $myWHT;
    exit 1;
fi

# Time for some housekeeping
# Let's backup some original files
$myRED; echo "### Backing up some original files."; $myWHT
mkdir -p /etc/suricata/0ld
if [ -f /etc/suricata/classification.config ]
  then mv /etc/suricata/classification.config /etc/suricata/0ld/
fi
if [ -f /etc/suricata/reference.config ]
  then mv /etc/suricata/reference.config /etc/suricata/0ld/
fi
if [ -f /etc/suricata/suricata.yaml ]
  then mv /etc/suricata/suricata.yaml /etc/suricata/0ld/
fi
if [ -f /etc/rc.local ]
  then mv /etc/rc.local /etc/rc.local.backup
fi
if [ -f /var/www/kibana/app/dashboards/default.json ]
  then mv /var/www/kibana/app/dashboards/default.json /var/www/kibana/app/dashboards/default.json.backup
fi

# Let's create some files and folders
$myRED; echo "### Creating some files and folders."; $myWHT
mkdir -p /etc/suricata/rules
mkdir -p /var/log/suricata
touch /var/log/suricata/eve.json
chmod 644 /var/log/suricata/eve.json

# Let's replace some files
$myRED; echo "### Copying prepared configs to destination folders."; $myWHT
cp suricata.yaml /etc/suricata/
cp myNSM.json /var/www/kibana/app/dashboards/default.json
cp myNSM.json /var/www/kibana/app/dashboards/
chmod 664 /var/www/kibana/app/dashboards/default.json
chmod 664 /var/www/kibana/app/dashboards/myNSM.json

# File must be present due to a suricata config bug
$myRED; echo "### Creating empty threshold.config."; $myWHT
touch /etc/suricata/threshold.config

# Let's create a test rule, just in case
$myRED; echo "### Creating test.rules."; $myWHT
tee /etc/suricata/rules/test.rules <<EOF
alert ip any any -> any any (msg:"ICMP detected"; sid:2; rev:1;)
EOF

# Let's patch oinkmaster.conf with update url
$myRED; echo "### Patching oinkmaster.conf with update url."; $myWHT
sed -i.bak 's#\# url = http://www.bleedingsnort.com/downloads/bleeding.rules.tar.gz#url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz#' /etc/oinkmaster.conf

# Let's pull some rules
$myRED; echo "### Downloading latest rules."; $myWHT;
myOINKMASTER=$(which oinkmaster)
if [ -x $myOINKMASTER ];
  then $myRED; echo "### Found oinkmaster, now pulling some rules."; $myWHT;
    $myOINKMASTER -C /etc/oinkmaster.conf -o /etc/suricata/rules/;
  else $myRED; echo "### Could not find Oinkmaster, something went wrong."; $myWHT;
    exit 1
fi

# Let's make sure there is no checksuming and offloading
$myred; echo "### Making sure NIC offloading and checksuming is disabled"; $myWHT;
ethtool --offload $myETH rx off tx off
ethtool -K $myETH gso off gro off

tee /etc/rc.local <<EOF
#!/bin/sh -e

# Disable NIC offloading and checksuming
ethtool --offload $myETH rx off tx off
ethtool -K $myETH gso off gro off

# NIC needs to be in promiscious mode to capture all traffic
ip link set $myETH promisc on

exit 0
EOF
chmod 755 /etc/rc.local

# Let's make sure the rules will be checked / updated on a daily basis
$myRED; echo "### Creating oinkmaster cron.job in crontab."; $myWHT
cp /etc/crontab /etc/crontab.backup
tee -a /etc/crontab <<EOF

# Oinkmaster daily rules check
00 7    * * *   root    $(which oinkmaster) -C /etc/oinkmaster.conf -o /etc/suricata/rules/ 

# Make sure suricata log stays accessible
5  *    * * *   root    chmod 644 /var/log/suricata/eve.json

EOF

# Let's create a suricata upstart config
$myRED; echo "### Creating suricata upstart config."; $myWHT
tee /etc/init/suricata.conf <<EOF
# Suricata
description "Intruder Detection System Daemon" 
start on runlevel [2345]
stop on runlevel [!2345]
expect fork
exec suricata -D --pidfile /var/run/suricata.pid -c /etc/suricata/suricata.yaml -i $myETH
EOF

# Let's create a logstash config
$myRED; echo "### Creating logstash config."; $myWHT
tee /etc/logstash/conf.d/logstash.conf <<EOF
input {
  file {
    path => ["/var/log/suricata/eve.json"]
    codec =>   json
    type => "SuricataIDPS-logs"
  }

}

filter {
  if [type] == "SuricataIDPS-logs" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }

  if [src_ip]  {
    geoip {
      source => "src_ip"
      target => "geoip"
      database => "/opt/logstash/vendor/geoip/GeoLiteCity.dat"
      add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
      add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
    }
    mutate {
      convert => [ "[geoip][coordinates]", "float" ]
    }
  }
}

output {
  elasticsearch {
    host => localhost
  }
}
EOF

# Let's prepare apache for a new site and auth-digest
a2enmod auth_digest proxy proxy_http ssl
mv myNSM.pwd /etc/apache2/
tee /etc/apache2/sites-available/myNSM-ssl.conf <<EOF
<IfModule mod_ssl.c>
        <VirtualHost _default_:443>
                ServerAdmin webmaster@localhost
                DocumentRoot /var/www/kibana

                ErrorLog /error.log
                CustomLog /access.log combined

                SSLEngine on
                SSLCertificateFile      /etc/apache2/myNSM.crt
                SSLCertificateKeyFile /etc/apache2/mySERVER.key

                SSLProtocol +TLSv1.2
                SSLCompression off
                SSLHonorCipherOrder on
                SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK
                ProxyRequests off
                ProxyPass /elasticsearch/ http://localhost:9200/
                <Location /elasticsearch/>
                        ProxyPassReverse /
                        SSLRequireSSL
                </Location>

                <Directory /var/www/kibana>
                        SSLRequireSSL
                        AuthType Digest
                        AuthName "myNSM"
                        AuthDigestProvider file
                        AuthUserFile /etc/apache2/myNSM.pwd
                        Require valid-user
                        Options Indexes FollowSymLinks
                        AllowOverride None
                </Directory>

                <FilesMatch "\.(cgi|shtml|phtml|php)$">
                        SSLOptions +StdEnvVars
                </FilesMatch>
                <Directory /usr/lib/cgi-bin>
                        SSLOptions +StdEnvVars
                </Directory>

                BrowserMatch "MSIE [2-6]"                                 nokeepalive ssl-unclean-shutdown                                 downgrade-1.0 force-response-1.0
                # MSIE 7 and newer should be able to use keepalive
                BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown

        </VirtualHost>
</IfModule>
EOF
sleep 3
a2ensite myNSM-ssl.conf
a2dissite 000-default.conf

# Let's create the webserver certificates
$myRED; echo "### Creating certificates."; $myWHT
openssl genrsa -out mySERVER.key 8192
openssl req -new -key mySERVER.key -out myNSM.csr
openssl x509 -req -days 3650 -in myNSM.csr -signkey mySERVER.key -out myNSM.crt
mv mySERVER.key myNSM.crt /etc/apache2/

# Let's patch ports.conf to disable listen on port 80
$myRED; echo "### Patching ports.conf to disable listen on port 80."; $myWHT
sed -i.bak 's#Listen 80#\#Listen 80#' /etc/apache2/ports.conf

# Let's patch kibana config.js for ssl
$myRED; echo "### Patching kibana config.js for ssl."; $myWHT
sed -i.bak 's#elasticsearch: "http://"+window.location.hostname+":9200",#elasticsearch: "https://"+window.location.hostname+"/elasticsearch/",#' /var/www/kibana/config.js

# Let's configure automatic start of services
$myRED; echo "### Configuring automatic start of services."; $myWHT
update-rc.d elasticsearch defaults 95 10
update-rc.d logstash defaults
service suricata start
service apache2 restart
service elasticsearch start
service logstash start

# Done
myIP=$(ifconfig $myETH | grep "inet addr:" | awk '{ print $2 }' | cut -d: -f2)
$myRED; echo "### You can access kibana dashboard from your browser via https://"$myIP; $myWHT
$myRED; echo "### Done."; $myWHT
exit 0
