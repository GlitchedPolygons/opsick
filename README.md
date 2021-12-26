# opsick
## A password manager featuring tha _sickest opsec_, ayye

### What is this?
It's an open-source password manager. This specific repo here is the server-side application, which is written in plain, naked, good old C. No sharp, no plusplus thingy. Just C.

### But why tho...
Because why not? Every other pw manager out there is either just so bloated, closed-source (proprietary) or slow. Or maybe even all of these things together, dang it!

This right here is as lightweight and as performant as it can possibly get, and you can basically do with it whatever you like. Neat, right?

### Dependencies
* LibUUID
* LibPQ

These you can install using the following commands;

#### Linux:
      - Arch:                sudo pacman -S uuid-devel postgresql-libs
      - Debian/*buntu:       sudo apt-get install uuid-dev postgresql-server-dev-all postgresql-client-common postgresql-common
      - CentOS/Fedora/RHEL:  sudo dnf install uuid-devel libpq-devel
#### FreeBSD:
      - (UUID already included in OS)
#### Windows:
      - Uninstall Windows
      - Proceed with one of the variants above...
      
The rest of the dependencies should be installed automatically with the below `git clone` command (git submodules) and the subsequent cmake command (third party libs were added to this project as CMake `add_subdirectory()` wherever possible).

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

Whether you built from sauce or grabbed pre-built binaries: it doesn't matter in terms of configuration. All user-configurable settings reside in the opsick db (postgres) inside the "settings" table (as key-value pairs). 

You can customize your instance-specific user settings to whatever you need/want them to be (e.g. defining a user creation password, changing port numbers, etc...).
By default, opsick listens to port `6677` by the way..

Check out the `config.h` file for more infos about what can be customized.

Opsick needs to know how to connect to the opsick postgres database: it looks for a read-only text file at the following path:

* Linux
* * `/var/opt/opsick/dbconn`
* macOS
* * `/usr/local/share/opsick/dbconn`

In that text file you must have a valid `libpq` connection string. Check out the [postgres documentation](https://www.postgresql.org/docs/8.1/libpq.html#LIBPQ-CONNECT) for more information.

### API Documentation

Available here: https://glitchedpolygons.github.io/opsick/files.html
