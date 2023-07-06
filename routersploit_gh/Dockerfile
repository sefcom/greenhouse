FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt -y update && apt -y upgrade
RUN apt -y install iproute2 python3 python3-pip curl unzip docker docker-compose vim net-tools
RUN apt update
RUN apt install -y awscli

RUN curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
RUN chmod +x /usr/local/bin/docker-compose

RUN pip3 install setuptools-rust
RUN pip3 install selenium=="3.141.0"
RUN apt -y install libnss3 libnspr4 wget jq
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - 
RUN echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list
RUN apt-get update && apt-get -y install google-chrome-stable
COPY routersploit_ghpatched /routersploit
RUN pip3 install -r routersploit/requirements.txt
RUN CHROMEVERSION=`google-chrome-stable --version | tr "." " " | awk '{print $3}'`; DRIVERVERSION=`curl https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROMEVERSION`; wget https://chromedriver.storage.googleapis.com/$DRIVERVERSION/chromedriver_linux64.zip
RUN unzip /chromedriver_linux64.zip
RUN cp chromedriver /routersploit/routersploit_ghpatched

RUN pip3 install lxml

COPY ubuntu.tar /ubuntu.tar
COPY GH_PATH_TRAVERSAL /GH_PATH_TRAVERSAL
COPY exploits.list /exploits.list

ADD routersploit-log-parser /routersploit-log-parser
COPY entrypoint.sh /

EXPOSE 80
EXPOSE 1900/tcp
EXPOSE 1900/udp
CMD ["/entrypoint.sh"]
# CMD ["/bin/bash"]
