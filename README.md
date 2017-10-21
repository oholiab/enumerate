Enumerate
=========
> A tool for inspecting subdomains for IP ownership information

enumerate an OSINT tool which takes a list of domains (like that produced by
[sublist3r](https://github.com/aboul3la/Sublist3r)) and producing an sqlite3
database mapping the domains to the first found host IP for that domain and the
announced route that the IP belongs to along with ASN and the ASN name.

This is helpful for determining what network services and hosting providers a
given organization is using. 

# Installation

    go install -v github.com/oholiab/enumerate

# Non-golang dependencies

You will need the `whois` binary installed and in your `$PATH` and `sqlite3`.

# Usage

With `$GOBIN` in your `$PATH`:

    $ enumerate -h
    Usage of enumerate:
      -db string
            path to output database (default "./enumerate.db")
      -list string
            path to domain list (default "./enumerate.txt")
    $ enumerate -list somelist.txt -db domains.db

Then you can query your database using sqlite3 to do further investigatory work,
for example:
    
```sqlite3
select name, owner, asn from records 
  inner join routes on records.route_id = routes.id 
  where owner != "Amazon";
```

Will show you all of the domains and which AS name and number they belong to,
excluding all IPs owned by Amazon.

# Limitations
This is a pretty dumb tool which will always take the first of multiple records
for any given lookup - so for instance if `whois` returns multiple route
advertisements, you'll only ever get one.

Largely though, the point of the tool is enumeration of the ASs for a given
domain, so this isn't too much of a problem - treat it as a jumping off point
for further investigation.

# Hacking
I've vendored dependencies using [dep](https://github.com/golang/dep). With it
installed:

    git clone https://github.com/oholiab/enumerate
    cd enumerate
    make deps
