sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update

sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88

# sudo add-apt-repository \
#    "deb [arch=arm64] https://download.docker.com/linux/ubuntu \
#    $(lsb_release -cs) \
#    stable"

sudo add-apt-repository \
   "deb [arch=arm64] https://download.docker.com/linux/ubuntu \
   artful \
   stable"
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io

#apt-cache madison docker-ce
#sudo apt-get install docker-ce=<VERSION_STRING> docker-ce-cli=<VERSION_STRING> containerd.io
#sudo usermod -aG docker your-user
