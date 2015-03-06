GeoIP Legacy Apache Module
==========================

Important Note
--------------

This API is for the GeoIP Legacy format (dat). To read the MaxMind DB format
(mmdb) used by GeoIP2, please see
[mod_maxminddb](https://github.com/maxmind/mod_maxminddb)

Description
-----------

The mod_geoip2 module embeds GeoIP Legacy database lookups into the
Apache web server. It is only capable of looking up the IP of a client
that connects to the web server, as opposed to looking up arbitrary
addresses.

This module works with Apache 2. Please use
[mod_geoip](http://www.maxmind.com/download/geoip/api/mod_geoip/mod_geoip-latest.tar.gz)
with Apache 1.

Installation
------------

You can [download
mod_geoip2](https://github.com/maxmind/geoip-api-mod_geoip2/releases)
from GitHub or get the latest development version from
[GitHub](https://github.com/maxmind/geoip-api-mod_geoip2). See the
`INSTALL` file in the tarball for installation details.

Overview
--------

The mod_geoip2 module uses the libGeoIP library to look up geolocation
information for a client as part of the http request process. This
module is free software, and is licensed under the [Apache
license](http://www.apache.org/licenses/LICENSE-2.0.html).

To compile and install this module, you must first install [libGeoIP
1.4.3](/?page_id=44#MaxMind-Supported_APIs) or newer.

The mod_geoip2 module takes effect either during request header parsing
phase or the post read request phase, depending on whether it is
configured for server-wide use or for a specific location/directory.

When enabled, the module looks at the incoming IP address and sets some
variables which provide geolocation information for that IP. The
variables it set depend on the specific GeoIP Legacy database being used
(Country, City, ISP, etc.). These variables can be set in either the
request notes table, the environment or both depending on the server
configuration.

Configuration
-------------

With the exception of `GeoIPEnable`, all GeoIP configuration
directives must be placed in the server-wide context of the main server
config. (Please see [Server vs Directory
context](#Server_vs_Directory_context) for a full explanation). After
installing the module, make sure that

    GeoIPEnable On

is set in your Apache configuration file or an `.htaccess` file. This
will call the GeoIP Legacy Country database from its default location
(e.g. /usr/local/share/GeoIP/GeoIP.dat)

If you want to specify options, for example to use a different database
or to pass caching options, you can use the `GeoIPDBFile` directive:

### File and Caching Directives

    GeoIPDBFile /path/to/GeoIP.dat [GeoIPFlag]

For example:

    GeoIPDBFile /usr/local/share/GeoIP/GeoIP.dat MemoryCache
    GeoIPDBFile /usr/local/share/GeoIP/GeoIPOrg.dat Standard

The default GeoIPFlag value is Standard, which does not perform any
caching, but uses the least memory. To turn on memory caching use:

    GeoIPDBFile /path/to/GeoIP.dat MemoryCache

The memory cache option can use a large amount of memory. We recommend
that you use Memory Caching only for the smaller database files, such as
GeoIP Legacy Country and GeoIP Legacy ISP.

Another MemoryCache option is MMapCache, which uses the the `mmap`
system call to map the database file into memory.

If you would like the API to check to see if your local GeoIP Legacy
files have been updated, set the `CheckCache` flag:

    GeoIPDBFile /path/to/GeoIP.dat CheckCache

Before making a call to the database, geoip will check the GeoIP.dat
file to see if it has changed. If it has, then it will reload the file.
With this option, you do not have to restart Apache when you update your
GeoIP Legacy databases.

If you would like to turn on partial memory caching, use the
`IndexCache` flag:

    GeoIPDBFile /path/to/GeoIP.dat IndexCache

The IndexCache option caches the most frequently accessed index portion
of the database, resulting in faster lookups than StandardCache, but
less memory usage than MemoryCache. This is especially useful for larger
databases such as GeoIP Legacy Organization and GeoIP Legacy City. For
the GeoIP Legacy Country, Region and Netspeed databases, setting the
IndexCache option just causes the C API to use the MemoryCache.

Currently, multiple GeoIPFlags options can not be combined.

### Enabling UTF-8 Output

You may change the output charset from ISO-8859-1 (Latin-1) to UTF-8
with this directive:

    GeoIPEnableUTF8 On

By default mod_geoip2 sets variables in both the notes table and
environment. For performance reasons you may want to set only the one
you use. To do so, use the `GeoIPOutput` configuration directive:

### Output Variable Location

    GeoIPOutput Notes   # Sets the Apache notes table only
    GeoIPOutput Env     # Sets environment variables only
    GeoIPOutput Request # Sets input headers with the geo location information
    GeoIPOutput All     # Sets all three (default behaviour)

### Proxy-Related Directives

By default, this module will simply look at the IP address of the
client. However, if the client is using a proxy, this will be the
address of the proxy. You can use the `GeoIPScanProxyHeaders` directive
to look at proxy-related headers.

    GeoIPScanProxyHeaders On

When this is set, the module will look at several other sources for the
IP address, in this order:

-   The `HTTP_CLIENT_IP` environment variable (set by Apache).
-   The `HTTP_X_FORWARDED_FOR` environment variable (set by Apache).
-   The `X-Forwarded-For` for header (set by a proxy).
-   The `HTTP_REMOTE_ADDR` environment variable (set by Apache).

This module will use the first IP address it finds in one of these
locations *instead* of the IP address the client connected from.

Some of these variables may contain a comma-separate list of IP
addresses (when a client goes through multiple proxies). In this case,
the default behavior is to use the first IP address. You can set the
`GeoIPUseLastXForwardedForIP` directive to use the last address instead:

    GeoIPUseLastXForwardedForIP On

Or use `GeoIPUseFirstNonPrivateXForwardedForIP` to use the first non
private IP Address.

    GeoIPUseFirstNonPrivateXForwardedForIP On

Apache 2.4 users using mod_remoteip to pick the IP address of the user
should disable GeoIPScanProxyHeaders. Mod_geoip2 will use whatever
mod_remoteip provides.

    GeoIPScanProxyHeaderField FieldName

Sometimes it is useful to use another field as the source for the
client's IP address. You can set this directive to tell this module
which header to look at in order to determine the client's IP address.

Output Variables
----------------

As noted above, these variables can be set in either the Apache request
notes table, the environment, or both. The specific variables which are
set depend on the database you are using.

### GeoIP Country Edition Output Variables

#### GEOIP_ADDR

The address used to calculate the GeoIP output.

#### GEOIP_CONTINENT_CODE

A two-character code for the continent associated with the IP address.
The possible codes are:

-   **AF** - Africa
-   **AS** - Asia
-   **EU** - Europe
-   **NA** - North America
-   **OC** - Oceania
-   **SA** - South America

#### GEOIP_COUNTRY_CODE

A two-character [ISO 3166-1](http://en.wikipedia.org/wiki/ISO_3166-1)
country code for the country associated with the IP address. In addition
to the standard codes, we may also return one of the following:

-   **A1** - an [anonymous proxy](/?p=384).
-   **A2** - a [satellite provider](/?p=385).
-   **EU** - an IP in a block used by multiple [European](/?p=386)
    countries.
-   **AP** - an IP in a block used by multiple [Asia/Pacific
    region](/?p=386) countries.

The **US** country code is returned for IP addresses associated with
overseas US military bases.

#### GEOIP_COUNTRY_NAME

The country name associated with the IP address.

### GeoIP Region Edition Output Variables

#### GEOIP_ADDR

The address used to calculate the GeoIP output.

#### GEOIP_COUNTRY_CODE

A two-character [ISO 3166-1](http://en.wikipedia.org/wiki/ISO_3166-1)
country code for the country associated with the IP address. In addition
to the standard codes, we may also return one of the following:

-   **A1** - an [anonymous proxy](/?page_id=23#anonproxy).
-   **A2** - a [satellite provider](/?page_id=23#satellite).
-   **EU** - an IP in a block used by multiple
    [European](/?page_id=23#euapcodes) countries.
-   **AP** - an IP in a block used by multiple [Asia/Pacific
    region](/?page_id=23#euapcodes) countries.

The **US** country code is returned for IP addresses associated with
overseas US military bases.

#### GEOIP_REGION_NAME

The region name associated with the IP address.

#### GEOIP_REGION

A two character [ISO-3166-2](http://en.wikipedia.org/wiki/ISO_3166-2) or
[FIPS 10-4](http://en.wikipedia.org/wiki/FIPS_10-4) code for the
state/region associated with the IP address.

For the US and Canada, we return an ISO-3166-2 code. In addition to the
standard ISO codes, we may also return one of the following:

-   **AA** - Armed Forces America
-   **AE** - Armed Forces Europe
-   **AP** - Armed Forces Pacific

We return a FIPS code for all other countries.

We provide a [CSV file which maps our region codes to region
names](http://www.maxmind.com/download/geoip/misc/region_codes.csv). The
columns are ISO country code, region code (FIPS or ISO), and the region
name.

### GeoIP City Edition Output Variables

#### GEOIP_ADDR

The address used to calculate the GeoIP output.

#### GEOIP_CONTINENT_CODE

A two-character code for the continent associated with the IP address.
The possible codes are:

-   **AF** - Africa
-   **AS** - Asia
-   **EU** - Europe
-   **NA** - North America
-   **OC** - Oceania
-   **SA** - South America

#### GEOIP_COUNTRY_CODE

A two-character [ISO 3166-1](http://en.wikipedia.org/wiki/ISO_3166-1)
country code for the country associated with the IP address. In addition
to the standard codes, we may also return one of the following:

-   **A1** - an [anonymous proxy](/?page_id=23#anonproxy).
-   **A2** - a [satellite provider](/?page_id=23#satellite).
-   **EU** - an IP in a block used by multiple
    [European](/?page_id=23#euapcodes) countries.
-   **AP** - an IP in a block used by multiple [Asia/Pacific
    region](/?page_id=23#euapcodes) countries.

The **US** country code is returned for IP addresses associated with
overseas US military bases.

#### GEOIP_REGION

A two character [ISO-3166-2](http://en.wikipedia.org/wiki/ISO_3166-2) or
[FIPS 10-4](http://en.wikipedia.org/wiki/FIPS_10-4) code for the
state/region associated with the IP address.

For the US and Canada, we return an ISO-3166-2 code. In addition to the
standard ISO codes, we may also return one of the following:

-   **AA** - Armed Forces America
-   **AE** - Armed Forces Europe
-   **AP** - Armed Forces Pacific

We return a FIPS code for all other countries.

We provide a [CSV file which maps our region codes to region
names](http://www.maxmind.com/download/geoip/misc/region_codes.csv). The
columns are ISO country code, region code (FIPS or ISO), and the region
name.

#### GEOIP_REGION_NAME

The region name associated with the IP address.

#### GEOIP_CITY

The city or town name associated with the IP address. See our [list of
cities](http://www.maxmind.com/GeoIPCity-534-Location.csv) to see all
the possible return values. This list is updated on a regular basis.

#### GEOIP_METRO_CODE

The metro code associated with the IP address. These are only available
for IP addresses in the US. MaxMind returns the [same metro codes as the
Google AdWords
API](https://developers.google.com/adwords/api/docs/appendix/cities-DMAregions).

#### GEOIP_AREA_CODE

The telephone area code associated with the IP address. These are only
available for IP addresses in the US.

#### GEOIP_LATITUDE

The latitude associated with the IP address.

#### GEOIP_LONGITUDE

The longitude associated with the IP address.

#### GEOIP_POSTAL_CODE

The postal code associated with the IP address. These are available for
some IP addresses in the US, Canada, Germany, and United Kingdom.

### GeoIP ISP Edition Output Variables

#### GEOIP_ADDR

The address used to calculate the GeoIP output.

#### GEOIP_ISP

The name of the ISP associated with the IP address.

### GeoIP Organization Edition Output Variables

#### GEOIP_ADDR

The address used to calculate the GeoIP output.

#### GEOIP_ORGANIZATION

The name of the organization associated with the IP address.

### GeoIP Netspeed Edition Output Variables

#### GEOIP_ADDR

The address used to calculate the GeoIP output.

#### GEOIP_NETSPEED

The network speed associated with the IP address. This can be one of the
following values:

-   **Dialup**
-   **Cable/DSL**
-   **Corporate**
-   **Cellular**

### GeoIPv6 Edition (experimental) Output Variables

#### GEOIP_ADDR

The address used to calculate the GeoIP output.

#### GEOIP_CONTINENT_CODE_V6

A two-character code for the continent associated with the IP address.
The possible codes are:

-   **AF** - Africa
-   **AS** - Asia
-   **EU** - Europe
-   **NA** - North America
-   **OC** - Oceania
-   **SA** - South America

#### GEOIP_COUNTRY_CODE_V6

A two-character [ISO 3166-1](http://en.wikipedia.org/wiki/ISO_3166-1)
country code for the country associated with the IP address. In addition
to the standard codes, we may also return one of the following:

-   **A1** - an [anonymous proxy](/?page_id=23#anonproxy).
-   **A2** - a [satellite provider](/?page_id=23#satellite).
-   **EU** - an IP in a block used by multiple
    [European](/?page_id=23#euapcodes) countries.
-   **AP** - an IP in a block used by multiple [Asia/Pacific
    region](/?page_id=23#euapcodes) countries.

The **US** country code is returned for IP addresses associated with
overseas US military bases.

#### GEOIP_COUNTRY_NAME_V6

The country name associated with the IP address.

Examples
--------

Here are some examples of how you can use mod_geoip2.

### Redirecting a client based on country

This example show you how to redirect a client based on the country code
that GeoIP sets.

    GeoIPEnable On
    GeoIPDBFile /path/to/GeoIP.dat

    # Redirect one country
    RewriteEngine on
    RewriteCond %{ENV:GEOIP_COUNTRY_CODE} ^CA$
    RewriteRule ^(.*)$ http://www.canada.com$1 [R,L]

    # Redirect multiple countries to a single page
    RewriteEngine on
    RewriteCond %{ENV:GEOIP_COUNTRY_CODE} ^(CA|US|MX)$
    RewriteRule ^(.*)$ http://www.northamerica.com$1 [R,L]

### Blocking a client based on country

This example show you how to block clients based on the country code
that GeoIP sets.

    GeoIPEnable On
    GeoIPDBFile /path/to/GeoIP.dat

    SetEnvIf GEOIP_COUNTRY_CODE CN BlockCountry
    SetEnvIf GEOIP_COUNTRY_CODE RU BlockCountry
    # ... place more countries here

    Deny from env=BlockCountry

### Allowing clients based on country

This example show you how to allow only clients from specific countries.

    GeoIPEnable On
    GeoIPDBFile /path/to/GeoIP.dat

    SetEnvIf GEOIP_COUNTRY_CODE US AllowCountry
    SetEnvIf GEOIP_COUNTRY_CODE CA AllowCountry
    SetEnvIf GEOIP_COUNTRY_CODE MX AllowCountry
    # ... place more countries here

    Deny from all
    Allow from env=AllowCountry

### Server vs Directory context

All directives except GeoIPEnable are server config only, i.e., you type
it only once per server config. Otherwise the latest wins.

``` {.lang:default .decode:true}
<IfModule mod_geoip.c>
  GeoIPEnable Off
  GeoIPEnableUTF8 On
  GeoIPOutput Env
  GeoIPDBFile /usr/local/share/GeoIP/GeoIP.dat MemoryCache
  GeoIPDBFile /usr/local/share/GeoIP/GeoIPCity.dat MemoryCache
  GeoIPDBFile /usr/local/share/GeoIP/GeoIPOrg.dat MemoryCache
</IfModule>
```

GeoIPEnable is useful in server or directory context. For example:

GeoIP is only available for a specific location:

``` {.lang:default .decode:true}
<IfModule mod_geoip.c>
  GeoIPEnable Off
  GeoIPEnableUTF8 On
  GeoIPOutput Env
  GeoIPDBFile /usr/local/share/GeoIP/GeoIP.dat MemoryCache
</IfModule>

# GeoIP information is avail only inside /xxx
<Location /geoip-enabled>
  GeoIPEnable On
  ...
</Location>

<Location /other>
  ...
</Location>
```

GeoIP is available for all locations:

``` {.lang:default .decode:true}
<IfModule mod_geoip.c>
  GeoIPEnable On
  GeoIPEnableUTF8 On
  GeoIPOutput Env
  GeoIPDBFile /usr/local/share/GeoIP/GeoIP.dat MemoryCache
</IfModule>

# This doesn't work, because it's already been enabled in the server-wide
# config!
<Location /geoip-enabled>
  GeoIPEnable On
</Location>

<Location /geoip-disabled>
  GeoIPEnable Off
</Location>
```

Memory Usage
------------

Starting with mod_geoip2 version 1.2.1, all Apache child processes
share the same database when you set the MemoryCache or MMapCache flag.

Memory usage is about the same as the database file size, no matter how
many child processes Apache spawns. The only thing to remember is ask
Apache to update if your database changes. Use the graceful restart
option to do so without stopping Apache.

Performance
-----------

For improved performance, you may want to enable mod_geoip only for
specific HTML pages. If you want to use the mod_geoip module site-wide,
you may still be able to only use it for HTML pages and not images. To
restrict the pages where mod_geoip2 is used, place the `GeoIPEnable On`
directive inside a , or directive, see:
[httpd.apache.org/docs/2.0/sections.html](http://httpd.apache.org/docs/2.0/sections.html)

Troubleshooting
---------------

If the module is not working, make sure that the httpd user (e.g.
nobody) has read access to the GeoIP database file(s) you are using.

If the GeoIP variables do not show up please make sure that the client
IP address is not on a private network such as 10.0.0.0/8, 172.16.0.0/12
or 192.168.0.0/16. GeoIP can only look up public IP addresses.

------

This file was generated by running

  pandoc --from html --to markdown

Using the pre-generated HTML from
http://dev.maxmind.com/geoip/legacy/mod_geoip2 as the input.
