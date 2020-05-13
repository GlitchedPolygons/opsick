# opsick
## A password manager featuring tha _sickest opsec_, ayye

### What is this?
It's an open-source password manager. This specific repo here is the server-side application, which is written in plain, naked, good old C. No sharp, no plusplus thingy. Just C.

### But why tho...
Because why not? Every other pw manager out there is either just so bloated, closed-source proprietary or slow. Or maybe even all of these things together, dang it!

This right here is as lightweight and as performant as it can possibly get, and you can basically do with it whatever you like. Neat, right?

### Dependencies
* PostgreSQL
* * LibPQ

These two you can install using the following commands;

#### Linux:
      - Arch:                sudo pacman -S postgresql postgresql-libs
      - Debian/*buntu:       sudo apt-get install postgresql libpq-dev
      - CentOS/Fedora/RHEL:  https://wiki.postgresql.org/wiki/YUM_Installation
                             or
                             https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-centos-8
#### macOS:
      - brew install postgresql libpq
#### Windows:
      - Uninstall Windows
      - Proceed with one of the variants above...
      
The rest of the dependencies should be installed automatically with the below `git clone` command (git submodules) and the subsequent cmake command (third party libs were added to this project as CMake `add_subdirectory()` wherever possible).

### How to build
```
git clone --recursive https://github.com/GlitchedPolygons/opsick
cd opsick
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### How to configure

Whether you built from sauce or grabbed pre-built binaries: it doesn't matter in terms of configuration. To configure your opsick instance, you need to open the `config.toml` file inside the directory where the opsick executable resides.

Inside that file, you can customize your instance-specific user settings to whatever you need/want them to be (e.g. defining a user creation password, changing port numbers, etc...).
By default, opsick listens to port `6677` by the way..
