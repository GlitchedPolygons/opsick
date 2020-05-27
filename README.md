# opsick
## A password manager featuring tha _sickest opsec_, ayye

### What is this?
It's an open-source password manager. This specific repo here is the server-side application, which is written in plain, naked, good old C. No sharp, no plusplus thingy. Just C.

### But why tho...
Because why not? Every other pw manager out there is either just so bloated, closed-source proprietary or slow. Or maybe even all of these things together, dang it!

This right here is as lightweight and as performant as it can possibly get, and you can basically do with it whatever you like. Neat, right?

### Dependencies
* LibUUID
* PostgreSQL
* * LibPQ

These you can install using the following commands;

#### Linux:
      - Arch:                sudo pacman -S postgresql postgresql-libs uuid-devel
      - Debian/*buntu:       sudo apt-get install postgresql libpq-dev uuid-dev
      - - Note that on Ubuntu it's possible that you need to pass `-DPostgreSQL_TYPE_INCLUDE_DIR=/usr/include/postgresql/` for CMake to detect PostgreSQL on your system!
      - CentOS/Fedora/RHEL:  sudo dnf install libpq-devel uuid-devel
#### macOS:
      - brew install postgresql libpq
#### Windows:
      - Uninstall Windows
      - Proceed with one of the variants above...
      
The rest of the dependencies should be installed automatically with the below `git clone` command (git submodules) and the subsequent cmake command (third party libs were added to this project as CMake `add_subdirectory()` wherever possible).

If you want to host the postgres database on the same server alongside opsick (thus reachable over `localhost`), check out the **awesome** postgres setup guide provided by DigitalOcean:

- CentOS 8: 
https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-centos-8

- Ubuntu 20:   
https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-ubuntu-20-04

Then you only need to run the SQL script(s) inside the `setup/postgres` folder! 
(Execute these as the `postgres` user, and ensure that the opsick db user and database were created correctly with all tables, privileges, etc...)

### How to build

#### Cloning this repo

Navigate into a directory where you wish to clone the opsick repository into. Then, run:

`git clone --recursive https://github.com/GlitchedPolygons/opsick`

#### Building

If you choose to build from src, make sure that you have the necessary build tools installed, such as [CMake](https://cmake.org), a compiler, and so on...

Then, either run the [build.sh](https://github.com/GlitchedPolygons/opsick/blob/master/build.sh) shell script **OR** execute the following commands:

```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### How to configure

Whether you built from sauce or grabbed pre-built binaries: it doesn't matter in terms of configuration. To configure your opsick instance, you need to open the `config.toml` file inside the directory where the opsick executable resides.

Inside that file, you can customize your instance-specific user settings to whatever you need/want them to be (e.g. defining a user creation password, changing port numbers, etc...).
By default, opsick listens to port `6677` by the way..
