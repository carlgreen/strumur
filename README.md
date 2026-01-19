Strumur
=======

**Strumur** is an implementation of a DLNA/UPnP media server. If you have files on a computing type thing and something that can play files off of a 'server', this might be useful to you.

As this is currently as much a learning excercise and portfolio piece as it is a useful software, I have pseudo-implemented a lot of things that existing libraries could probably handle better.

Usage
-----

```shell
cargo build --release
./target/release/strumur ~/Music/
```

or just

```shell
cargo run -- ~/Music/
```

Why
---

I wasn't happy with the DLNA server that was easiest to get working on my NAS, and I wanted a project to show that I have some idea of what I'm doing with this programming stuff. This seemed like a project that covers a bunch of interesting areas — e.g. networking, file system, file parsing, search language parsing, etc. — as well as being something that is of use to me.

I'm also trying to get better at Rust, and this has exposed me to a bunch of Rust stuff that I've been mostly able to avoid. I still like it.

Once I get this to a certain state where I'm not so embarrassed by the WIP-ness of it all this section will likely be removed. Until then, hi mum and dad.

Limitations
-----------

Where to begin?

 - Doesn't maintain state or send updates so isn't compliant with the standards
 - Only supports FLAC files so far, becuase most of my music is FLAC

Contributing
------------

I'm using this to learn so I'm not looking for contributions at this stage. Hot takes are welcome though.
