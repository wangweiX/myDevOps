
#!/bin/bash
#-------------------------------------------------------------------------------------------------
# Install Docker On Ubuntu 16.04
# @author https://wangwei.one
# @date 2018/12/15
# @refer https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-16-04
#-------------------------------------------------------------------------------------------------

# First, in order to ensure the downloads are valid, add the GPG key for the official Docker repository to your system
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# Add the Docker repository to APT sources:
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# update the package database with the Docker packages from the newly added repo:
sudo apt-get update

# Make sure you are about to install from the Docker repo instead of the default Ubuntu 16.04 repo:
apt-cache policy docker-ce

# Finally, install Docker:
sudo apt-get install -y docker-ce

# add user to docker group
sudo usermod -aG docker ${USER}

# apply the new group membership
su - ${USER}

# Docker should now be installed, the daemon started, and the process enabled to start on boot. Check that it's running:
sudo systemctl status docker
