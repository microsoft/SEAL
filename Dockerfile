# @Author: George Onoufriou <GeorgeRaven, DreamingRaven>
# @Date:   2020-01-22

# this dockerfile is standalone, and downloads its own copy of seal
FROM archlinux:latest

# variable for user username to use in the container
ARG user_name=archie

# variable for user password to use in the container
ARG user_password=archer

# variable for which branch to use of seal when building it
ARG branch=master

# creating basic gpu capable archlinux system
RUN pacman -Syyuu sudo git base-devel fish cmake clang --noconfirm

# creating user with the desired permissions (NOPASS required for pikaur stages)
RUN useradd -m -p $(openssl passwd -1 ${user_password}) ${user_name} && \
    echo "${user_name} ALL=(ALL) ALL" >> /etc/sudoers && \
    echo "${user_name} ALL=(ALL) NOPASSWD:/usr/bin/pacman" >> /etc/sudoers && \
    echo "exec fish" >> /root/.bashrc

# # Commented out block installs an AUR helper and how to use it
# # swapping to our newly created user
# USER ${user_name}
# # clone, build, and install pikaur
# RUN mkdir -p /home/${user_name}/git && \
#     cd /home/${user_name}/git && \
#     git clone "https://github.com/actionless/pikaur" && \
#     cd /home/${user_name}/git/pikaur && \
#     makepkg -s --noconfirm && \
#     echo "${user_password}" | sudo -S pacman -U *pkg.tar.xz --noconfirm
# USER root
# # install more specific packages from community and AUR as needed
# RUN sudo -u ${user_name} pikaur -S --noconfirm git

USER ${user_name}

# creates some quality of life for inside the container
RUN echo "cd ~" >> /home/${user_name}/.bashrc && \
    echo "exec fish" >> /home/${user_name}/.bashrc

# clone, checkout and build seal
RUN mkdir -p /home/${user_name}/git && \
    cd ~/git && \
    git clone "https://github.com/microsoft/seal" && \
    cd ~/git/seal && \
    git checkout ${branch} && \
    cd native/src && \
    cmake . && \
    make && \
    cd ../.. && \
    cd native/examples && \
    cmake . && \
    make && \
    cd ../..
