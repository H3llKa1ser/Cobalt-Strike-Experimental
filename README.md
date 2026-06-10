# Cobalt-Strike-Experimental

Experimental BOFs and Aggressor Scripts for Cobalt Strike C2

# Compiling

Use MinGW (cross-compile from Linux is the common workflow):

### x64

    x86_64-w64-mingw32-gcc -c hostinfo.c -o hostinfo.x64.o -masm=intel -Wall

### x86

    i686-w64-mingw32-gcc   -c hostinfo.c -o hostinfo.x86.o -masm=intel -Wall

# Resources

https://hackyourmom.com/en/pryvatnist/posibnyk-z-cobaltstrike-8-beacon-object-filey/

https://cobalt-strike.github.io/community_kit/
