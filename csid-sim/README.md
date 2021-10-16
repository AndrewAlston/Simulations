# CSID Simulation #

Build using cmake/make

### Brief introduction ###

This code aims to simulate the behavior found in: 
https://datatracker.ietf.org/doc/draft-filsfilscheng-spring-srv6-srh-compression

This is a work in progress - and currently the code to emulate the next behavior is functional,
behavior for the replace behavior to follow shortly.

### How to run this ###

The code has 4 basic parameters to specify source and destination address, locator, and a segment list.

The segment list is a comma delimited list, with each element comprised of 3 seperate elements that specify sid size,
the sid itself and the behavior to apply.

Sid sizes must be specified as either 16 or 32 bit.  
Sid's as specified in hexadecimal and prepended with 0x.
Behavior is specified as either 2 or 3 - for next and replace respectively.

By way of example - to simulate a packet ingressing and being encapsulated with an SRH, and then moving
through 2 16bit SID's (0xaaaa and 0xbbbb) followed by a 32bit SID (0xccccdddd) using locator 2001:db8:1010:: 
we would run:

./csid-sim -s 2001:db8:1::1 -d 2001:db8:2::1 -l 2001:db8:1010:: -s 16_0xaaaa_2,16_0xbbbb_2,32_0xccccdddd_2

Where 2001:db8:1::1 is the unicast source, 2001:db8:2::1 is the unicast destination, 
2001:db8:1010:: is the locator, and the -s argument is the segment list.

This would produce:

```Original packet 2001:db8:fefe::10 -> 2001:db8:eeee::20
[NEXT 16 bit] DA change [2001:db8:eeee::20 --> 2001:db8:101:eeff:ccdd:aabb::]
    Forwarding [2001:db8:fefe::10 -> 2001:db8:101:eeff:ccdd:aabb::]
[NEXT 16 bit] DA change [2001:db8:101:eeff:ccdd:aabb:: --> 2001:db8:101:ccdd:aabb::]
    Forwarding [2001:db8:fefe::10 -> 2001:db8:101:ccdd:aabb::]
[NEXT 16 bit] DA change [2001:db8:101:ccdd:aabb:: --> 2001:db8:101:aabb::]
    Forwarding [2001:db8:fefe::10 -> 2001:db8:101:aabb::]
[NEXT 16 bit] DA change [2001:db8:101:aabb:: --> 2001:db8:eeee::20]
    Forwarding [2001:db8:fefe::10 -> 2001:db8:eeee::20]
```

Replace behavior has yet to be implemented - this will follow shortly

Will also be adding flags to hex dump at each step.

Pull requests/comments welcome.


