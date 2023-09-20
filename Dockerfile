FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y apt-utils
RUN apt-get -y install apt-utils git curl radare2 python2 python3 python3-venv python3-pip wget sudo docker telnet net-tools iputils-ping iptables iproute2 libguestfs-tools p7zip-full p7zip-rar zip libpq-dev vim netcat socat qemu-system
RUN apt update
RUN apt install -y dnsutils jq

RUN python3 -m venv /root/venv

RUN mkdir -p /work/firmwares
RUN cd /work && git clone -q --recursive https://github.com/pr0v3rbs/FirmAE

COPY FirmAEreplacements/install.sh /work/FirmAE/install.sh
COPY FirmAEreplacements/v2.3.3.tar.gz /work/FirmAE/v2.3.3.tar.gz

RUN cd /work/FirmAE && ./download.sh
RUN cd /work/FirmAE && ./install.sh
RUN ln -s /bin/ntfs-3g /bin/mount.ntfs-3g

RUN git clone -q https://github.com/angr/angr-dev
RUN cd /angr-dev && . /root/venv/bin/activate && ./setup.sh -i -D "archinfo pyvex cle claripy ailment angr angr-doc binaries"

RUN git clone -q https://github.com/davidribyrne/cramfs
RUN cd /cramfs && make && make install

RUN mkdir /work/FirmAE/targetfs
RUN mkdir -p /host

RUN rm -rf /work/FirmAE/analyses/routersploit
RUN cd /work/FirmAE/analyses && git clone -q -n https://github.com/threat9/routersploit
RUN cd /work/FirmAE/analyses/routersploit && git checkout 4eefc7e
RUN cd /work/FirmAE/analyses/routersploit && git apply /work/FirmAE/analyses/routersploit_patch
RUN cd /work/FirmAE/analyses/routersploit && pip install -r requirements.txt

COPY FirmAEreplacements/makeNetwork.py /work/FirmAE/scripts/makeNetwork.py
COPY FirmAEreplacements/delete.sh /work/FirmAE/scripts/delete.sh
COPY FirmAEreplacements/inferFile.sh /work/FirmAE/scripts/inferFile.sh
COPY FirmAEreplacements/test_emulation.sh /work/FirmAE/scripts/test_emulation.sh
COPY FirmAEreplacements/umount.sh /work/FirmAE/scripts/umount.sh

COPY FirmAEreplacements/extractor.py /work/FirmAE/sources/extractor/extractor.py

COPY FirmAEreplacements/firmae.config /work/FirmAE/firmae.config
COPY FirmAEreplacements/run.sh /work/FirmAE/run.sh
COPY FirmAEreplacements/initializer.py /work/FirmAE/analyses/initializer.py

RUN rm /work/FirmAE/v2.3.3.tar.gz

COPY Greenhouse /gh

RUN apt-get install -y python-is-python3

COPY chrome104.deb /chrome104.deb
RUN apt-get install -y --allow-downgrades /chrome104.deb
RUN rm /chrome104.deb

RUN CHROMEVERSION=`/usr/bin/google-chrome --version | tr "." " " | awk '{print $3}'`; DRIVERVERSION=`curl https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROMEVERSION`; wget https://chromedriver.storage.googleapis.com/$DRIVERVERSION/chromedriver_linux64.zip
RUN unzip /chromedriver_linux64.zip
RUN cp chromedriver /work/FirmAE/chromedriver
RUN cp chromedriver /work/FirmAE/analyses/chromedriver
RUN cp chromedriver /gh
RUN cp chromedriver /gh/analysis
RUN rm /chromedriver_linux64.zip

COPY ubuntu.tar /ubuntu.tar

RUN git clone -q https://github.com/sviehb/jefferson

COPY squashfs-tools.tar.gz /
RUN tar -xzf squashfs-tools.tar.gz
RUN chown -R root /squashfs-tools
RUN cd /squashfs-tools/squashfs-tools && make && make install
RUN rm /squashfs-tools.tar.gz

RUN . /root/venv/bin/activate \ 
		&& pip uninstall -y selenium \
		&& pip install selenium=="3.141.0"
		
RUN . /root/venv/bin/activate \
		 && pip install wheel \
		  && pip install -r /gh/requirements.txt

RUN . /root/venv/bin/activate \
		 && cd /jefferson \
		  && pip install -r requirements.txt \
		  && python3 setup.py install
		  
RUN . /root/venv/bin/activate \
		 && pip install paramiko \
		 && pip uninstall pyelftools -y \
		 && pip install pyelftools==0.29
		  
RUN chmod 777 /usr/bin/sudo
COPY testimage.tar.gz /testimage.tar.gz
RUN tar -xzf /testimage.tar.gz
RUN rm testimage.tar.gz

RUN mkdir /routersploit
COPY /routersploit_gh/routersploit_ghpatched /routersploit/routersploit_gh
RUN pip3 install -r /routersploit/routersploit_gh/requirements.txt
RUN pip3 install lxml pycrypto

RUN curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
RUN chmod +x /usr/local/bin/docker-compose

COPY routersploit_gh/GH_PATH_TRAVERSAL /routersploit/GH_PATH_TRAVERSAL
COPY routersploit_gh/exploits.list /routersploit/exploits.list
ADD routersploit_gh/routersploit-log-parser /routersploit/routersploit_gh/routersploit-log-parser

COPY entrypoint.sh /gh/entrypoint.sh
COPY docker_init.sh /gh/docker_init.sh
COPY docker_k8_run.sh /gh/docker_k8_run.sh


COPY crashing_inputs /crashing_inputs

COPY routersploit_gh/run_routersploit.sh /routersploit
COPY test.sh /gh/test.sh
COPY run.sh /gh/run.sh

ENV TERM=xterm
